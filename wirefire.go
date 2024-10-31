package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	stock "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"wirefire/internal/coordinator"
)

func init() {
	// flags related to http endpoint configuration
	flag.String("http.host", "127.0.0.1", "http port to bind to")
	flag.Int("http.port", 8080, "http port to bind to")
	flag.Bool("http.debug", false, "enable /debug http endpoint")

	// system settings
	flag.String("key", "", "coordination server's private key")

	// flag related to logging
	flag.Bool("log.verbose", false, "enable verbose log output")
}

func main() {
	var err error

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGKILL, syscall.SIGTERM)
	defer stop()

	flag.Parse()
	viper.AutomaticEnv()
	_ = viper.BindPFlags(flag.CommandLine)

	var logger zerolog.Logger
	{
		var out io.Writer = os.Stdout
		if fi, _ := os.Stdout.Stat(); (fi.Mode() & os.ModeCharDevice) != 0 { // configure pretty-print logger if stdout is a terminal / char device
			out = zerolog.ConsoleWriter{Out: os.Stdout}
		}

		logger = zerolog.New(out).Level(zerolog.InfoLevel).With().Timestamp().Logger()
		ctx = logger.WithContext(ctx) // associate default logger with root context

		if viper.IsSet("log.verbose") && viper.GetBool("log.verbose") { // configure verbose logging
			logger = logger.Level(zerolog.DebugLevel)
		}

		log.Logger = logger // set as default logger
	}

	if !viper.IsSet("key") {
		log.Fatal().Msg("missing coordination server's private key")
	}

	var serverKey key.MachinePrivate
	if serverKey, err = ParsePrivateKey(viper.GetString("key")); err != nil {
		log.Fatal().Err(err).Msg("failed to parse server's private key")
	}

	// create new router with a set of stock middlewares registered
	r := chi.NewRouter()
	r.Use(stock.NoCache, stock.Recoverer, stock.RequestID)

	r.Handle("/ts2021", coordinator.NewHandler(serverKey))
	r.Get("/key", KeyHandler(serverKey))

	// mount profiler endpoints to /debug
	if viper.IsSet("http.debug") && viper.GetBool("http.debug") {
		r.Mount("/debug", stock.Profiler())
	}

	addr := fmt.Sprintf("%s:%d", viper.GetString("http.host"), viper.GetInt("http.port"))
	srv := &http.Server{Addr: addr, Handler: r, BaseContext: func(_ net.Listener) context.Context { return ctx }}

	log.Info().Str("addr", addr).Msg("starting http server")
	if err = srv.ListenAndServeTLS("./.certs/cert.pem", "./.certs/key.pem"); err != nil {
		log.Fatal().Err(err).Send()
	}
}

// KeyHandler serves tailcfg.OverTLSPublicKeyResponse over /key endpoint
func KeyHandler(private key.MachinePrivate) http.HandlerFunc {
	public := private.Public()

	return func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("v"); v != "" {
			if clientVersion, err := strconv.Atoi(v); err != nil {
				http.Error(w, "invalid version", http.StatusBadRequest)
			} else if clientVersion >= coordinator.NoiseCapabilityVersion {
				var resp = &tailcfg.OverTLSPublicKeyResponse{PublicKey: public}
				if err = json.NewEncoder(w).Encode(resp); err != nil {
					http.Error(w, "failed to encode response", http.StatusInternalServerError)
				}
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}
}
