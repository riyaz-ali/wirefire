package coordinator

import (
	"context"
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"github.com/riyaz-ali/wirefire/internal/config"
	"github.com/riyaz-ali/wirefire/internal/database"
	"github.com/riyaz-ali/wirefire/internal/domain"
	"github.com/riyaz-ali/wirefire/internal/util"
	"github.com/rs/zerolog"
	"net/url"
	"strings"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/rands"
	"time"
)

// MachineRegister implements handler for the /machine/register endpoint served over Noise channel.
//
// The /machine/register endpoint is the first endpoint that the node talks to start the authentication process.
// This endpoint is used by the node to register its Noise public-key and Node public-key and kick-off a user authentication process.
//
// Upon successful authentication, the machine registration request is marked as successful and the node is added to the selected tailnet.
func MachineRegister(peer key.MachinePublic, pool *sqlitex.Pool) util.HandlerFunc[tailcfg.RegisterRequest, tailcfg.RegisterResponse] {
	cfg := config.MustValidate(config.Read[Config]())

	return func(ctx context.Context, req tailcfg.RegisterRequest) (_ *tailcfg.RegisterResponse, err error) {
		log := zerolog.Ctx(ctx).With().Str("peer", peer.String()).Logger()

		if req.Version < SupportedCapabilityVersion {
			return &tailcfg.RegisterResponse{Error: UnsupportedClientVersionMessage}, nil
		}

		var conn = pool.Get(ctx)
		defer pool.Put(conn)

		// @NOTE: do not use transaction here as it'd prevent the connection from seeing
		//        changes made by concurrent processes (namely, oidc endpoint marking request as authenticated).
		//
		//        We start a transaction below only if a machine for the peer is found, in which case we make
		//        changes to machine data and stuff and do not depend on any concurrent processes.
		//
		// defer sqlitex.Save(conn)(&err)

		var machine *domain.Machine
		if machine, err = database.FetchOne(conn, domain.GetMachineByKey(peer)); err != nil {
			return nil, err
		}

		if machine == nil { // this is a new machine that we are seeing for the first time
			log.Debug().Msg("no machine found for peer")

			if req.Followup != "" { // client is polling / following up on the status of authentication
				log.Debug().Msg("peer requesting follow-up; entering follow-up loop")

				var authUrl *url.URL
				if authUrl, err = url.Parse(req.Followup); err != nil {
					log.Error().Err(err).Msg("failed to parse follow-up url")
					return &tailcfg.RegisterResponse{Error: err.Error()}, nil
				}

				if authUrl.Host != cfg.BaseUrl.Host || !strings.HasSuffix(authUrl.Path, "/oidc/login") {
					log.Error().Msg("invalid follow-up url")

					return &tailcfg.RegisterResponse{Error: "invalid follow-up request url"}, nil
				}

				flow := authUrl.Query().Get("flow")
				if flow == "" {
					return &tailcfg.RegisterResponse{Error: "invalid follow-up request url"}, nil
				}

				return followup(ctx, conn, peer, flow)
			}

			if req.Auth != nil && req.Auth.AuthKey != "" {
				log.Error().Msg("peer requesting auth-key based authentication")

				// TODO(@riyaz): add support for auth key based authentication (see: https://tailscale.com/kb/1085/auth-keys)
				return &tailcfg.RegisterResponse{Error: "Auth key based authentication is not supported"}, nil
			}

			rid := rands.HexString(8)
			if _, err = database.Exec(conn, domain.CreateRegistrationRequest(rid, peer, req)); err != nil {
				return &tailcfg.RegisterResponse{Error: err.Error()}, nil
			}

			authUrl := cfg.BaseUrl.JoinPath("/oidc/login")

			q := authUrl.Query()
			q.Set("flow", rid)
			authUrl.RawQuery = q.Encode()

			log.Debug().Str("registration_id", rid).Msg("starting oidc login")

			return &tailcfg.RegisterResponse{AuthURL: authUrl.String()}, nil
		} else {
			defer sqlitex.Save(conn)(&err) // run the following block in a transaction

			log = log.With().Int("tailnet", machine.Tailnet.ID).Str("machine", machine.CompleteName()).Logger()
			log.Debug().Msg("found machine for peer")

			if machine.IsExpired() { // node has expired
				log.Debug().Msg("machine key has expired")
				return &tailcfg.RegisterResponse{NodeKeyExpired: true}, nil
			}

			// indicated expiry in the request has passed
			if !req.Expiry.IsZero() && req.Expiry.Before(time.Now()) {
				log.Debug().Msgf("requested expiry %s has passed; expiring machine key", req.Expiry)
				if _, err = database.Exec(conn, domain.DeleteNode(machine)); err != nil {
					return nil, err
				}

				return &tailcfg.RegisterResponse{NodeKeyExpired: true}, nil
			}

			// update the machine hostname and save all associated data
			sanitizeHostname := dnsname.SanitizeHostname(req.Hostinfo.Hostname)
			if machine.Name != sanitizeHostname { // has the hostname changed? if yes, we need to generate a new name_idx
				log.Debug().Msgf("renaming machine to %s", sanitizeHostname)

				var nextIdx = 0 // first machine with the given name has name_idx = 0
				if ni, err := database.FetchOne[int](conn, domain.GetNextNameIndex(machine.Tailnet, sanitizeHostname)); err != nil {
					return nil, err
				} else if ni != nil {
					nextIdx = *ni
				}

				machine.Name = sanitizeHostname
				machine.NameIdx = nextIdx
			}

			if _, err = database.Exec(conn, domain.SaveMachine(machine)); err != nil {
				return nil, err
			}

			return &tailcfg.RegisterResponse{
				MachineAuthorized: true,
				User: tailcfg.User{
					ID:          tailcfg.UserID(machine.Owner.ID),
					LoginName:   machine.Owner.Name,
					DisplayName: machine.Owner.Name,
					Created:     machine.Owner.CreatedAt,
				},
				Login: tailcfg.Login{
					ID:          tailcfg.LoginID(machine.Owner.ID),
					LoginName:   machine.Owner.Name,
					DisplayName: machine.Owner.Name,
				},
			}, nil
		}
	}
}

// followup polls for domain.RegistrationRequest changes (every 2 seconds)
// until either the RegistrationRequest.Authenticated becomes true or the client disconnects or the authentication fails.
func followup(ctx context.Context, conn *sqlite.Conn, peer key.MachinePublic, flow string) (*tailcfg.RegisterResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("peer", peer.String()).Str("flow", flow).Logger()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rr, err := database.FetchOne(conn, domain.RegistrationRequestById(flow))
			if err != nil || rr == nil {
				log.Err(err).Msg("failed to fetch request")
				return &tailcfg.RegisterResponse{MachineAuthorized: false, Error: "something went wrong"}, nil
			}

			if len(rr.Error) != 0 {
				return &tailcfg.RegisterResponse{MachineAuthorized: false, Error: rr.Error}, nil
			}

			if rr.Authenticated {
				log.Debug().Msg("request authenticated")

				return &tailcfg.RegisterResponse{
					MachineAuthorized: len(rr.Error) == 0,
					Error:             rr.Error,
					User: tailcfg.User{
						ID:          tailcfg.UserID(rr.User.ID),
						LoginName:   rr.User.Name,
						DisplayName: rr.User.Name,
						Created:     rr.User.CreatedAt,
					},
					Login: tailcfg.Login{
						ID:          tailcfg.LoginID(rr.User.ID),
						LoginName:   rr.User.Name,
						DisplayName: rr.User.Name,
					},
				}, nil
			}

		case <-ctx.Done():
			log.Debug().Err(ctx.Err()).Msg("context expired")
			return nil, nil
		}
	}
}
