// Command httpflip is a small HTTP service for uploading and retrieving files.
//
// Uploads and deletes require a bearer token; downloads do not. See
// README.md for the operational runbook.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mropc/http-flip/internal/auth"
	"github.com/mropc/http-flip/internal/server"
	"github.com/mropc/http-flip/internal/store"
)

// version is overridable at build time with
// -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "httpflip: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := server.DefaultConfig()
	var (
		addr    = flag.String("addr", cfg.Addr, "listen address")
		dataDir = flag.String("data-dir", "/data",
			"directory for stored objects")
		tokenFile = flag.String("tokens-file", "/etc/httpflip/tokens",
			"bearer token file")
		maxUpload = flag.Int64("max-upload-bytes", cfg.MaxUploadBytes,
			"maximum size of a single uploaded file in bytes")
		logLevel = flag.String("log-level", "info",
			"log level: debug, info, warn or error")
		shutdownFor = flag.Duration("shutdown-timeout", cfg.ShutdownTimeout,
			"how long to wait for in-flight requests on shutdown")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("httpflip", version)
		return nil
	}

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	// Tokens are loaded first, and fatally: a service that cannot
	// authenticate anyone must not start and then look healthy to its probes.
	authn, err := auth.New(*tokenFile, log)
	if err != nil {
		return fmt.Errorf("cannot load bearer tokens: %w", err)
	}
	log.Info("loaded bearer tokens",
		"file", *tokenFile, "credentials", authn.Credentials())

	st, err := store.New(*dataDir, log)
	if err != nil {
		return fmt.Errorf("cannot open data directory: %w", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("closing data dir", "err", err)
		}
	}()

	cfg.Addr = *addr
	cfg.MaxUploadBytes = *maxUpload
	cfg.ShutdownTimeout = *shutdownFor

	srv, err := server.New(server.Options{
		Config: cfg,
		Store:  st,
		Auth:   authn,
		Logger: log,
	})
	if err != nil {
		return err
	}
	return serve(srv, log, cfg.ShutdownTimeout)
}

// serve runs srv until interrupted, then drains.
//
// OpenShift sends SIGTERM on every rollout and on every node drain, so handling
// it gracefully is the difference between a deploy nobody notices and one that
// fails a handful of in-progress uploads.
func serve(srv *server.Server, log *slog.Logger, timeout time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	// A second signal restores the default disposition, so an operator who
	// decides the drain is taking too long can force it with Ctrl-C.
	defer stop()

	// Bind before claiming to listen: a port that is already
	// taken must surface as a startup error, not as a
	// "listening" line followed by one.
	ln, err := srv.Listen()
	if err != nil {
		return err
	}
	log.Info("listening",
		"addr", srv.Addr(), "max_upload_bytes", srv.MaxUploadBytes())

	errc := make(chan error, 1)
	go func() {
		errc <- srv.Serve(ln)
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		stop()
		log.Info("shutting down", "timeout", timeout)
	}

	drain, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(drain); err != nil {
		return fmt.Errorf("shutdown did not complete: %w", err)
	}
	if err := <-errc; err != nil {
		return err
	}
	log.Info("stopped")
	return nil
}

// newLogger returns a JSON logger at the requested level, falling back to
// info for anything unrecognised with a warning on stderr so a typo does
// not pass silently.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		fmt.Fprintf(os.Stderr, "httpflip: unknown log level %q, using info\n",
			level)
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	}))
}
