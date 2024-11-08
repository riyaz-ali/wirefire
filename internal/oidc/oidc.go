// Package oidc provide functions and endpoint implementation to handle OIDC-based authentication
package oidc

import (
	"context"
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/pkg/errors"
	"github.com/riyaz-ali/wirefire/internal/config"
	"github.com/riyaz-ali/wirefire/internal/database"
	"github.com/riyaz-ali/wirefire/internal/domain"
	"github.com/riyaz-ali/wirefire/internal/ipam"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"tailscale.com/util/dnsname"
	"time"
)

//go:embed templates
var templates embed.FS

// Config is the OIDC configuration provided by the user
type Config struct {
	// Key is the coordination server's key.MachinePrivate key.
	// We use the key's hash to secure our csrf tokens.
	Key string `viper:"noise.private_key"`

	// Provider is the address of the authentication server.
	// The server must support /.well-known/openid-configuration endpoint
	Provider string `viper:"oidc.provider"`

	// OIDC client id and secret values
	ClientID     string `viper:"oidc.client_id"`
	ClientSecret string `viper:"oidc.client_secret"`

	// BaseUrl used to construct redirect urls
	BaseUrl *url.URL `viper:"server.url"`
}

func Handler(ctx context.Context, pool *sqlitex.Pool) http.Handler {
	cfg := config.MustValidate(config.Read[Config]())
	rs := NewRemoteService(ctx, cfg)

	r := chi.NewRouter()
	r.Use(NewAccessLog())
	r.Method(http.MethodGet, "/login", AuthStart(cfg, rs))
	r.Method(http.MethodGet, "/callback", AuthCallback(rs, pool))
	r.Method(http.MethodPost, "/callback", AuthComplete(rs, pool))

	// wrap all endpoints using csrf.Protect()
	csrfProtect := csrf.Protect(sha256.New().Sum([]byte(cfg.Key)),
		csrf.Secure(cfg.BaseUrl.Scheme == "https"), csrf.CookieName("csrf_token"))

	return csrfProtect(r)
}

// NewAccessLog returns a new middleware that sends its log output to the provided zerolog sink at the end of each request
func NewAccessLog() func(next http.Handler) http.Handler {
	return hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		zerolog.Ctx(r.Context()).Info().Str("method", r.Method).Str("path", r.URL.Path).Int("status", status).Send()
	})
}

// AuthStart serves the GET /login endpoint and starts the OIDC authentication flow
func AuthStart(cfg *Config, rs *RemoteService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// value of flow is not validated in any way here
		// this is taken verbatim from the request and will get passed to the /callback endpoint
		// where it will validate it, and return appropriate error
		if flow := r.URL.Query().Get("flow"); flow == "" {
			http.Error(w, "missing flow parameter", http.StatusBadRequest)
		} else {
			http.SetCookie(w, &http.Cookie{Name: "state", Value: flow, Secure: cfg.BaseUrl.Scheme == "https", HttpOnly: true})
			http.Redirect(w, r, rs.AuthCodeURL(flow), http.StatusFound)
		}
	}
}

// AuthCallback serves the GET /callback endpoint and handles OIDC token-exchange and validation.
// Upon successful validation, it renders a form with a list of tailnets that the user can join.
func AuthCallback(rs *RemoteService, pool *sqlitex.Pool) http.HandlerFunc {
	var tpl = template.Must(template.ParseFS(templates, "templates/*.html"))

	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx, log := r.Context(), zerolog.Ctx(r.Context())

		if ok, err := validateState(r, "state"); err != nil || !ok {
			http.Error(w, "invalid state", http.StatusBadRequest)

			return
		}

		conn := pool.Get(ctx)
		defer pool.Put(conn)

		var rr *domain.RegistrationRequest
		if rr, err = database.FetchOne(conn, domain.RegistrationRequestById(r.URL.Query().Get("state"))); err != nil || rr == nil {
			http.Error(w, "invalid flow", http.StatusNotFound)

			return
		}

		var raw string
		if raw, err = rs.Exchange(ctx, r.URL.Query().Get("code")); err != nil {
			log.Error().Err(err).Msg("failed to exchange code")
			http.Error(w, "failed to exchange code", http.StatusBadRequest)

			return
		}

		var token *oidc.IDToken
		if token, err = rs.Verify(ctx, raw); err != nil {
			log.Error().Err(err).Msg("failed to verify token")
			http.Error(w, "failed to verify token", http.StatusBadRequest)

			return
		}

		var claims domain.UserClaims
		if err = token.Claims(&claims); err != nil {
			log.Error().Err(err).Msg("failed to parse claims from token")
			http.Error(w, "failed to parse claims from token", http.StatusBadRequest)

			return
		}

		var user *domain.User
		if user, err = database.FetchOne(conn, domain.FindOrCreateUser(claims)); err != nil {
			http.Error(w, "failed to find or create user", http.StatusInternalServerError)

			return
		}

		var tailnets []*domain.Tailnet
		if tailnets, err = database.FetchMany(conn, domain.ListTailnets(user)); err != nil {
			log.Error().Err(err).Msg("failed to list tailnets")
			http.Error(w, "failed to list tailnets", http.StatusInternalServerError)

			return
		}

		raw = base64.StdEncoding.EncodeToString([]byte(raw)) // encode to base64 to prevent unwanted escaping when sent via html form
		params := map[string]any{csrf.TemplateTag: csrf.TemplateField(r), "rr": rr, "token": raw, "tailnets": tailnets}

		if err = tpl.ExecuteTemplate(w, "callback.html", params); err != nil {
			log.Error().Err(err).Msg("failed to render template")
			http.Error(w, "failed to render template", http.StatusInternalServerError)

			return
		}
	}
}

// AuthComplete serves the POST /callback endpoint and completes the authentication flow,
// adding the machine to the requested tailnet.
func AuthComplete(rs *RemoteService, pool *sqlitex.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, log := r.Context(), zerolog.Ctx(r.Context())

		var err error
		if err = r.ParseForm(); err != nil {
			http.Error(w, "failed to parse request", http.StatusBadRequest)

			return
		}

		var raw, _ = base64.StdEncoding.DecodeString(r.FormValue("token"))

		var token *oidc.IDToken
		if token, err = rs.Verify(ctx, string(raw)); err != nil {
			log.Error().Err(err).Msg("failed to verify token")
			http.Error(w, "failed to verify token", http.StatusBadRequest)

			return
		}

		conn := pool.Get(ctx)
		defer pool.Put(conn)

		var rr *domain.RegistrationRequest
		err = database.Tx(conn, func(conn *sqlite.Conn) error {
			if rr, err = database.FetchOne(conn, domain.RegistrationRequestById(r.FormValue("rid"))); err != nil {
				return err
			}

			var user *domain.User
			if user, err = database.FetchOne(conn, domain.UserBySubject(token.Subject)); err != nil {
				return err
			}

			tid, _ := strconv.ParseInt(r.FormValue("tailnet"), 10, 64)
			if member, _ := database.FetchOne(conn, domain.CheckMembership(user, tid)); member == nil || *member == false {
				return errors.New("user is not a member of the requested tailnet")
			}

			var tailnet *domain.Tailnet
			if tailnet, err = database.FetchOne(conn, domain.TailnetById(tid)); err != nil {
				return err
			}

			// create a new machine and add it to the tailnet
			var machine *domain.Machine
			if machine, err = database.FetchOne(conn, domain.GetMachineByKey(rr.NoiseKey)); err != nil {
				return err
			}

			if machine == nil { // create a new machine
				if machine, err = createMachine(conn, user, tailnet, rr); err != nil {
					return err
				}
			} else {
				// TODO(@riyaz): user has re-authenticated after node expiry (or logout); store updated params
			}

			rr.Authenticated = true
			rr.UserID = sql.Null[int]{Valid: true, V: user.ID}

			_, err = database.Exec(conn, domain.SaveRegistrationRequest(rr))
			return err
		})

		if err != nil {
			if rr != nil {
				rr.Authenticated, rr.Error = false, err.Error()
				_, _ = database.Exec(conn, domain.SaveRegistrationRequest(rr))
			}

			log.Error().Err(err).Msg("failed to complete authentication")
			http.Error(w, "failed to complete authentication", http.StatusInternalServerError)
		} else {
			_, _ = fmt.Fprintf(w, "Authentication successful! Please close this window")
		}
	}
}

func validateState(r *http.Request, param string) (_ bool, err error) {
	var queryStr = r.URL.Query().Get(param)

	var cookie *http.Cookie
	if cookie, err = r.Cookie(param); err != nil {
		return false, err
	}

	return queryStr == cookie.Value, nil
}

func createMachine(conn *sqlite.Conn, user *domain.User, tailnet *domain.Tailnet, req *domain.RegistrationRequest) (_ *domain.Machine, err error) {
	var machine = &domain.Machine{
		NoiseKey: req.NoiseKey,
		NodeKey:  req.Data.NodeKey,

		HostInfo:  req.Data.Hostinfo,
		Ephemeral: req.Data.Ephemeral,

		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(180 * 24 * time.Hour), // expires after 180 days

		TailnetID: tailnet.ID,
		Tailnet:   tailnet,
		UserID:    user.ID,
		Owner:     user,
	}

	// TODO(@riyaz): verify data.Hostinfo.RequestTags to ensure user has required permissions to apply those tags

	// sanitize host name and assign name index if required
	sanitizeHostname := dnsname.SanitizeHostname(req.Data.Hostinfo.Hostname)

	machine.Name = sanitizeHostname
	machine.NameIdx = 0 // first machine with the given name has name_idx = 0

	if ni, err := database.FetchOne[int](conn, domain.GetNextNameIndex(tailnet, sanitizeHostname)); err != nil {
		return nil, err
	} else if ni != nil {
		machine.NameIdx = *ni
	}

	predicate := func(ip netip.Addr) (bool, error) {
		exists, _ := database.FetchOne(conn, domain.CheckIpInTailnet(ip, tailnet))
		return *exists == false, nil
	}

	// assign ip address to the node
	if machine.IPv4, _, err = ipam.SelectIP(predicate); err != nil {
		return nil, err
	}

	if m, err := database.Exec(conn, domain.SaveMachine(machine)); err != nil {
		return nil, err
	} else {
		return m[0], nil
	}
}
