// Package coordinator implements the http backend for Tailscale 2021 Noise-based REST protocol
package coordinator

import (
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
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netutil"
	"tailscale.com/types/key"
	"time"
)

const (
	SupportedCapabilityVersion      = 68
	NoiseCapabilityVersion          = 28
	UnsupportedClientVersionMessage = "wirefire only support client version >= 1.48.0, please upgrade your client"
)

// NewHandler returns a new http.Handler that implement Tailscale's 2021 Noise-based REST protocol
func NewHandler(serverKey key.MachinePrivate) http.HandlerFunc {
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

		r.Handle("/", r.NotFoundHandler())

		// h2c protocol (un-encrypted http2 over http/1) is used over a Noise authenticated channel
		srv := &http.Server{Handler: h2c.NewHandler(r, &http2.Server{})}
		err = srv.Serve(netutil.NewOneConnListener(conn, nil))

		if err != nil && !errors.Is(err, io.EOF) {
			log.Err(err).Msg("failed to serve noise connection")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// NewAccessLog returns a new middleware that sends its log output to the provided zerolog sink at the end of each request
func NewAccessLog(peer key.MachinePublic) func(next http.Handler) http.Handler {
	return hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		sink := zerolog.Ctx(r.Context())
		sink.Info().Str("peer", peer.String()).Str("method", r.Method).
			Str("path", r.URL.Path).Int("status", status).Send()
	})
}
