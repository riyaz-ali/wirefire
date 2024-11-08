// Package coordinator implements the http backend for Tailscale 2021 Noise-based REST protocol
package coordinator

import (
	"crawshaw.io/sqlite/sqlitex"
	"github.com/go-chi/chi/v5"
	stock "github.com/go-chi/chi/v5/middleware"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"io"
	"net/http"
	"net/url"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netutil"
	"tailscale.com/types/key"
)

const (
	SupportedCapabilityVersion      = 68
	NoiseCapabilityVersion          = 28
	UnsupportedClientVersionMessage = "wirefire only support client version >= 1.48.0, please upgrade your client"
)

// Config is the subset of configuration relevant to the coordinator server
type Config struct {
	// BaseUrl is the url (optionally public) on which the coordinator is available
	BaseUrl *url.URL `viper:"server.url" validation:"required"`
}

// Upgrade returns a new http.Handler that implement Tailscale's 2021 Noise-based REST protocol
func Upgrade(serverKey key.MachinePrivate, pool *sqlitex.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		conn, err := controlhttp.AcceptHTTP(req.Context(), w, req, serverKey, nil)
		if err != nil {
			log.Err(err).Msg("failed to upgrade noise connection")
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		var logger zerolog.Logger
		logger = zerolog.Ctx(req.Context()).With().Str("peer", conn.Peer().String()).Logger()

		r := chi.NewRouter()
		r.Use(stock.NoCache, stock.Recoverer)
		r.Use(hlog.NewHandler(logger), NewAccessLog(conn.Peer()))

		r.Method(http.MethodPost, "/machine/register", MachineRegister(conn.Peer(), pool))
		r.Method(http.MethodPost, "/machine/map", MachineMap(conn.Peer(), pool))

		// h2c protocol (un-encrypted http2 over http/1) is used over a Noise authenticated channel
		srv := &http.Server{Handler: h2c.NewHandler(r, &http2.Server{})}
		err = srv.Serve(netutil.NewOneConnListener(conn, nil))

		if err != nil && !errors.Is(err, io.EOF) {
			log.Err(err).Msg("failed to serve noise connection")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// NewAccessLog returns a new middleware that sends its log output to the provided zerolog sink.
//
// The log is sent at the start of the request itself as /machine endpoints can engage in
// long-running operations, and we don't want to wait till the end to emit a log.
func NewAccessLog(peer key.MachinePublic) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sink := zerolog.Ctx(r.Context())
			sink.Info().Str("peer", peer.String()).Str("method", r.Method).Str("path", r.URL.Path).Send()

			next.ServeHTTP(w, r)
		})
	}
}
