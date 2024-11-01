package main

import (
	"context"
	"crawshaw.io/sqlite/sqlitex"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	stock "github.com/go-chi/chi/v5/middleware"
	"github.com/riyaz-ali/wirefire/internal/config"
	"github.com/riyaz-ali/wirefire/internal/coordinator"
	"github.com/riyaz-ali/wirefire/internal/database/schema"
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
)

// WirefireConfig is the base configuration for the core coordination service.
type WirefireConfig struct {
	Key string `viper:"key"`

	HTTP struct {
		Host  string `viper:"http.host" default:"127.0.0.1"`
		Port  int    `viper:"http.port" default:"8080"`
		Debug bool   `viper:"http.debug"`
	}

	Database struct {
		URL string `viper:"database.url"`
	}

	Log struct {
		Level zerolog.Level `viper:"log.level" default:"info"`
	}
}

func main() {
	var err error

	var configFile = flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	viper.SetConfigFile(*configFile)
	if err = viper.ReadInConfig(); err != nil {
		log.Fatal().Err(err).Msg("failed to read configuration file")
	}
	viper.AutomaticEnv() // override with any environment variables

	cfg := config.Read[WirefireConfig]() // read in the configuration value

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGKILL, syscall.SIGTERM)
	defer stop()

	var logger zerolog.Logger
	{
		var out io.Writer = os.Stdout
		if fi, _ := os.Stdout.Stat(); (fi.Mode() & os.ModeCharDevice) != 0 { // configure pretty-print logger if stdout is a terminal / char device
			out = zerolog.ConsoleWriter{Out: os.Stdout}
		}

		logger = zerolog.New(out).Level(cfg.Log.Level).With().Timestamp().Logger()
		ctx = logger.WithContext(ctx) // associate default logger with root context

		log.Logger = logger // set as default logger
	}

	var serverKey key.MachinePrivate // key must start with privkey:
	if cfg.Key == "" {
		log.Fatal().Msg("missing coordination server's private key")
	} else if err = serverKey.UnmarshalText([]byte(cfg.Key)); err != nil {
		log.Fatal().Err(err).Msg("failed to parse server's private key")
	}

	var pool *sqlitex.Pool
	{ // open and set up the database
		if pool, err = sqlitex.Open(cfg.Database.URL, 0 /* no additional flags */, 4); err != nil {
			log.Fatal().Err(err).Msg("failed to open database")
		}

		conn := pool.Get(ctx)
		if err = schema.Apply(conn); err != nil {
			log.Fatal().Err(err).Msg("failed to apply schema migration")
		}
		pool.Put(conn)
	}

	defer func() { _ = pool.Close() }() // close when server terminates

	// create new router with a set of stock middlewares registered
	r := chi.NewRouter()
	r.Use(stock.NoCache, stock.Recoverer, stock.RequestID)

	r.Get("/key", KeyHandler(serverKey))
	r.Handle("/ts2021", coordinator.Upgrade(serverKey))

	// mount profiler endpoints to /debug
	if cfg.HTTP.Debug {
		r.Mount("/debug", stock.Profiler())
	}

	addr := fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port)
	srv := &http.Server{Addr: addr, Handler: r, BaseContext: func(_ net.Listener) context.Context { return ctx }}

	log.Info().Str("addr", addr).Msg("starting http server")
	if err = srv.ListenAndServeTLS("./cert.pem", "./key.pem"); err != nil {
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
