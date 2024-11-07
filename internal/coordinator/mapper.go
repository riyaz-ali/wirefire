package coordinator

import (
	"bytes"
	"context"
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"github.com/riyaz-ali/tacl"
	"github.com/riyaz-ali/wirefire/internal/config"
	"github.com/riyaz-ali/wirefire/internal/database"
	"github.com/riyaz-ali/wirefire/internal/domain"
	"github.com/riyaz-ali/wirefire/internal/util"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"net/http"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
	"time"
)

type DnsConfig struct {
	MagicDns       bool   `viper:"dns.magic_dns" default:"true"`
	MagicDnsSuffix string `viper:"dns.magic_dns_suffix" default:"wirefire.net"`
}

// Adapt adapts the global DNS config for use with the given tailnet
func (c *DnsConfig) Adapt(tailnet *domain.Tailnet) *tailcfg.DNSConfig {
	var config = &tailcfg.DNSConfig{}

	sanitizeTailnetName := dnsname.SanitizeHostname(tailnet.Name)
	tailnetDomain := fmt.Sprintf("%s.%s", sanitizeTailnetName, c.MagicDnsSuffix)

	// routes is used to implement split dns; we use this when enabling magic dns
	var routes = make(map[string][]*dnstype.Resolver)

	if c.MagicDns {
		// If the value is an empty slice, that means the suffix should still
		// be handled by Tailscale's built-in resolver (100.100.100.100)
		routes[tailnetDomain] = nil

		config.Domains = append(config.Domains, tailnetDomain)
		config.Proxied = true

		// TODO(@riyaz): enable this when implementing https certificates
		//
		// if certsEnabled {
		// 	certDomains = append(certDomains, fmt.Sprintf("%s.%s", m.CompleteName(), tailnetDomain))
		// }
	}

	config.Routes = routes
	config.ExitNodeFilteredSet = []string{fmt.Sprintf(".%s", c.MagicDnsSuffix)}

	return config
}

// mapper returns a function that can be used to create tailcfg.MapResponse. It uses a
// closure to capture state between invocations and serve delta requests more efficiently.
func mapper() func(context.Context, *sqlite.Conn, *domain.Machine) (*tailcfg.MapResponse, error) {
	dns := config.MustValidate(config.Read[DnsConfig]())

	// save state between invocations to serve delta responses
	counter, derpChecksum := 1, ""

	return func(ctx context.Context, conn *sqlite.Conn, m *domain.Machine) (_ *tailcfg.MapResponse, err error) {
		log := zerolog.Ctx(ctx).With().Str("peer", m.NoiseKey.String()).Logger()
		delta := counter > 1
		defer func() { counter += 1 }()

		log.Debug().Msgf("preparing map response for machine(name=%q tailnet=%d) delta=%t", m.CompleteName(), m.Tailnet.ID, delta)
		var resp = &tailcfg.MapResponse{Domain: domain.SanitizeTailnetName(m.Tailnet.Name), ControlTime: util.ToPtr(time.Now().UTC())}

		if !delta {
			resp.Debug = &tailcfg.Debug{DisableLogTail: true}
		}

		var users = make(map[int]tailcfg.UserProfile)
		users[m.UserID] = m.Owner.AsUserProfile()

		var node = m.AsNode() // convert this machine to *tailcfg.Node

		// NOTE: trailing dot is important!
		node.Name = fmt.Sprintf("%s.%s.%s.", m.CompleteName(), dnsname.SanitizeHostname(m.Tailnet.Name), dns.MagicDnsSuffix)
		node.Online = util.ToPtr(true)

		resp.Node = node

		resp.DNSConfig = dns.Adapt(m.Tailnet) // build dns configuration

		derpMap, _ := viper.Get("derp.map").(*tailcfg.DERPMap)
		if checksum := util.Checksum(derpMap); delta || checksum != derpChecksum {
			derpChecksum = checksum
			resp.DERPMap = derpMap
		}

		// list all machines in this tailnet and build peer info
		var machines []*domain.Machine
		if machines, err = database.FetchMany(conn, domain.ListMachines(m.Tailnet)); err != nil {
			var se sqlite.Error
			if errors.As(err, &se) && se.Code == sqlite.SQLITE_INTERRUPT {
				return nil, nil // suppress interrupt errors
			}

			return nil, err
		}

		// convert domain.Machine to tacl.Peer for use below to compile packet filter rules
		var peers = make([]tacl.Machine, 0, len(machines)-1)

		for _, machine := range machines {
			if machine.ID == m.ID {
				continue // skip the current node
			}

			var peer = machine.AsNode()
			peer.Name = fmt.Sprintf("%s.%s.%s.", machine.CompleteName(), dnsname.SanitizeHostname(machine.Tailnet.Name), dns.MagicDnsSuffix)
			peer.Online = util.ToPtr(true) // TODO(@riyaz): check status using a presence service

			users[machine.UserID] = machine.Owner.AsUserProfile()

			// TODO(@riyaz): implement support for delta changes
			resp.Peers = append(resp.Peers, peer)
			peers = append(peers, machine)
		}

		// build packet filter rules based on the acl
		acl := m.Tailnet.Acl
		resp.PacketFilter = acl.BuildFilter(m, peers)

		// build ssh policy for the current node
		resp.SSHPolicy = acl.BuildSSHPolicy(m, peers,
			// TODO(@riyaz): this needs to be updated when we want to add support for ssh check action
			func(_ *tacl.SshRuleConfig) *tailcfg.SSHAction { return &tailcfg.SSHAction{Accept: true} },
		)

		resp.UserProfiles = make([]tailcfg.UserProfile, 0, len(users))
		for _, user := range users {
			resp.UserProfiles = append(resp.UserProfiles, user)
		}

		return resp, nil
	}
}

// MachineMap implements handler for the /machine/map endpoint served over the Noise channel.
//
// The /machine/map endpoint is used to the node to update its status and also to start a long-polling
// session to receive status updates from other nodes in the tailnet.
func MachineMap(peer key.MachinePublic, pool *sqlitex.Pool) util.StreamingHandlerFunc[tailcfg.MapRequest] {
	// utility function to get around defer-in-for-loop situations in serve() below
	var with = func(ctx context.Context, fn func(*sqlite.Conn) error) error {
		conn := pool.Get(ctx)
		defer pool.Put(conn)

		return fn(conn)
	}

	// Serve handles the long-running poll session and writes to sink everytime an update needs
	// to be sent to the client. Serve must be run in a goroutine to prevent it from blocking other request handling operations.
	var serve = func(ctx context.Context, sink chan<- *tailcfg.MapResponse, req tailcfg.MapRequest) error {
		log := zerolog.Ctx(ctx).With().Str("peer", peer.String()).Logger()
		mapFunc := mapper()

		// TODO(@riyaz): maybe make it configurable?
		var keepAlive = time.NewTicker(10 * time.Second)

		var conduit = make(chan struct{}, 20)
		var sync = time.NewTicker(5 * time.Second)
		defer sync.Stop()

		// The following two timestamps are used to buffer updates coming in from conduit.
		//
		// The way it works is that for every tailnet update we receive on the conduit, we only update
		// the lastUpdate timestamp, which cause lastSync and lastUpdate to go out of sync.
		//
		// Then, every 5-seconds, we check if lastSync.Before(lastUpdate) and send out new tailcfg.MapResponse if
		// we had received any updates in the last 5 seconds.
		//
		// This works independently of the keep-alive timer.
		now := time.Now()
		lastUpdate, lastSync := now, now

		// send out the first update immediately
		err := with(ctx, func(conn *sqlite.Conn) error {
			machine, err := database.FetchOne(conn, domain.GetMachineByKey(peer))
			if err != nil || machine == nil {
				return errors.Errorf("no machine found with key")
			}

			if resp, err := mapFunc(ctx, conn, machine); err != nil {
				return errors.Wrapf(err, "failed to prepare map response")
			} else if resp != nil {
				sink <- resp
			}

			return nil
		})

		if err != nil {
			return err
		}

		for { // go on forever! or at-least until power lasts ;P
			select {
			// conduit messages are updates received on a tailnet
			case <-conduit:
				lastUpdate = time.Now()

			// sync updates are ticker received every 5 seconds
			case <-sync.C:
				if lastSync.Before(lastUpdate) || true {
					var err = with(ctx, func(conn *sqlite.Conn) error {
						machine, err := database.FetchOne(conn, domain.GetMachineByKey(peer))
						if err != nil || machine == nil {
							return errors.Errorf("no machine found with key")
						}

						if resp, err := mapFunc(ctx, conn, machine); err != nil {
							return errors.Wrapf(err, "failed to prepare map response")
						} else if resp != nil {
							sink <- resp
						}

						return nil
					})

					if err != nil {
						return err
					}

					lastSync = lastUpdate
				} else {
					log.Debug().Msg("peer in-sync")
				}

			// keep-alive updates are ticker updates to send keep-alive pings to the peer, if it has requested one.
			case <-keepAlive.C:
				if req.KeepAlive {
					sink <- &tailcfg.MapResponse{KeepAlive: true}
				}

			// ctx.Done() signals that either some concurrent operation has cancelled the context or
			// the client has disconnected, either way, we terminate and clean-up our resources.
			case <-ctx.Done():
				return nil
			}
		}
	}

	return func(ctx context.Context, res http.ResponseWriter, req tailcfg.MapRequest) (err error) {
		log := zerolog.Ctx(ctx).With().Str("peer", peer.String()).Logger()

		if req.Version < SupportedCapabilityVersion {
			log.Warn().Msg("unsupported client version")
			return errors.New(UnsupportedClientVersionMessage)
		}

		conn := pool.Get(ctx)
		defer pool.Put(conn)

		var machine *domain.Machine
		if machine, err = database.FetchOne(conn, domain.GetMachineByKey(peer)); err != nil {
			log.Error().Err(err).Msg("failed to fetch machine")
			return err
		} else if machine == nil {
			log.Error().Msgf("no machine found for peer %s", peer.String())
			return errors.New("machine not found")
		}

		// if !req.Stream and req.Version >= 68 (always true for us), update the machine info
		// and send out a single MapResponse, only if req.OmitPeers is false.
		if !req.Stream {
			log.Debug().Msg("not streaming, updating machine info")

			machine.HostInfo = req.Hostinfo
			machine.DiscoKey = req.DiscoKey
			machine.NodeKey = req.NodeKey
			machine.Endpoints = req.Endpoints
			machine.LastSeen = util.ToPtr(time.Now())

			var m []*domain.Machine
			if m, err = database.Exec(conn, domain.SaveMachine(machine)); err != nil {
				return err
			}

			// TODO(@riyaz): notify connected clients about node status update

			machine = m[0]

			var mr *tailcfg.MapResponse // prepare full tailcfg.MapResponse to send to the client
			if mr, err = mapper()(ctx, conn, machine); err != nil {
				return err
			}

			var encoder = util.Json[tailcfg.MapResponse]
			if req.Compress == "zstd" {
				encoder = util.Zstd[tailcfg.MapResponse]
			}

			var buf bytes.Buffer
			if err = encoder(mr, &buf); err != nil {
				return err
			}

			// add 4-byte length to the payload
			var data = make([]byte, buf.Len()+4)
			binary.LittleEndian.PutUint32(data, uint32(buf.Len()))
			copy(data[4:], buf.Bytes())

			res.WriteHeader(http.StatusOK) // write all the headers and status
			_, err = res.Write(data)
			return err
		}

		// create a new wrapped context that is used to pass from encoder routine to serve routine
		serveCtx, stopServe := context.WithCancel(ctx)

		var g errgroup.Group // used to sync the following goroutines

		// start listening for updates in background
		var ch = make(chan *tailcfg.MapResponse)
		g.Go(func() error {
			defer close(ch) // make sure to always close sink to prevent request hang-up

			return serve(serveCtx, ch, req)
		})

		// serialize and send out updates over network
		g.Go(func() error {
			defer stopServe() // signal serve() to stop as well

			var encoder = util.Json[tailcfg.MapResponse]
			if req.Compress == "zstd" {
				encoder = util.Zstd[tailcfg.MapResponse]
			}

			res.WriteHeader(http.StatusOK)
			var buf = bytes.NewBuffer(make([]byte, 0, 4096)) // pre-allocate a buffer of 4kb
			for mr := range ch {
				if err = encoder(mr, buf); err != nil {
					return err
				}

				// add 4-byte length to the payload
				var data = make([]byte, buf.Len()+4)
				binary.LittleEndian.PutUint32(data, uint32(buf.Len()))
				copy(data[4:], buf.Bytes())

				if _, err = res.Write(data); err != nil {
					return err
				}

				if flusher, ok := res.(http.Flusher); ok {
					flusher.Flush()
				}

				buf.Reset()
			}

			return nil
		})

		return g.Wait()
	}
}
