// Package server exposes the upload and download HTTP surface.
//
// Uploads and deletes require a bearer token; downloads do not. That
// asymmetry is deliberate: a mutation needs an identity attached to it,
// whereas a download is a read of a capability URL whose path is ~282 bits
// of unguessable secret.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/mropc/http-flip/internal/auth"
	"github.com/mropc/http-flip/internal/store"
)

// DefaultMaxUploadBytes is the largest single file this service accepts unless
// an operator overrides it with -max-upload-bytes.
//
// This constant is the single source of truth for the upload limit. It is the
// one number a reader should be able to find with a grep for "upload limit",
// and it deliberately has no copy anywhere else: the -max-upload-bytes flag
// takes its default from it, the request-body cap and the streaming limit in
// handleUpload both derive from it at runtime, and the README quotes it.
//
// 10 MiB is a size that suits a document and image drop rather than a general
// file-transfer service. Raising it is one edit here plus a matching edit to
// the Route timeout, because the router's own timeout has to stay above the
// time a maximum-size upload takes on a slow link.
const DefaultMaxUploadBytes int64 = 10 << 20 // 10 MiB

// Config holds the tunables a Server needs. The zero value is not usable;
// use DefaultConfig and adjust.
type Config struct {
	// Addr is the listen address.
	Addr string

	// MaxUploadBytes is the largest single file accepted, in bytes. Defaults
	// to DefaultMaxUploadBytes; see that constant.
	MaxUploadBytes int64

	// ReadHeaderTimeout bounds how long a client may take to send request
	// headers. It is deliberately much shorter than ReadTimeout: a slow
	// body is a slow upload, but slow headers are only ever an attack or a
	// broken client, and the connection is held open throughout.
	ReadHeaderTimeout time.Duration
	// ReadTimeout bounds a whole request including the body, so a client
	// cannot hold a connection open indefinitely by trickling. It must stay
	// comfortably above the time a legitimate maximum-size upload takes.
	ReadTimeout time.Duration
	// WriteTimeout bounds a response, which matters most for downloads of
	// large objects over a slow link.
	WriteTimeout time.Duration
	// IdleTimeout bounds how long a keep-alive connection may sit unused.
	IdleTimeout time.Duration
	// MaxHeaderBytes caps request header size. Go's default is 1 MiB, which
	// is far more than this service needs.
	MaxHeaderBytes int
	// ShutdownTimeout is how long a graceful drain waits for in-flight
	// requests before the listener is closed regardless.
	ShutdownTimeout time.Duration
}

// DefaultConfig returns settings suited to DefaultMaxUploadBytes on a typical
// OpenShift pod behind a Route.
func DefaultConfig() Config {
	return Config{
		Addr:           ":8080",
		MaxUploadBytes: DefaultMaxUploadBytes,
		// Header timeouts are tight; body timeouts are generous, because a
		// maximum-size upload over a slow link legitimately takes minutes and
		// cutting it off would fail a well-behaved client.
		//
		// The body timeouts are tied to MaxUploadBytes rather than chosen on
		// their own: 10 MiB at roughly 35 KB/s sustained arrives just inside
		// 5m, which is a poor-consumer-mobile link. Anything tighter starts
		// failing real users, and the mitigation for a client that holds a
		// connection open is the network perimeter, not a smaller timeout.
		// If MaxUploadBytes is raised, revisit these.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ShutdownTimeout:   30 * time.Second,
	}
}

// Server routes and serves the upload and download API.
type Server struct {
	cfg   Config
	store *store.Store
	auth  *auth.Authenticator
	log   *slog.Logger
	http  *http.Server
}

// Construction errors. These are programming mistakes rather than runtime
// conditions, so they are plain sentinels rather than wrapped errors.
var (
	errNoStore       = errors.New("server: a store is required")
	errNoAuth        = errors.New("server: an authenticator is required")
	errNoUploadLimit = errors.New("server: MaxUploadBytes must be positive")
	errUploadLimit   = errors.New("server: MaxUploadBytes unreasonably large")
)

// maxSaneUploadBytes caps the operator flag so that MaxUploadBytes+bodySlack
// cannot overflow int64 and a typo cannot turn the volume into the only
// limit. 1 TiB is far above any sane document-drop use.
const maxSaneUploadBytes = int64(1) << 40

// Options are the collaborators New needs.
type Options struct {
	Config Config
	Store  *store.Store
	Auth   *auth.Authenticator
	Logger *slog.Logger
}

// New builds a Server. It does not listen; call Handler or Start.
func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errNoStore
	}
	if opts.Auth == nil {
		return nil, errNoAuth
	}
	if opts.Config.MaxUploadBytes <= 0 {
		return nil, errNoUploadLimit
	}
	if opts.Config.MaxUploadBytes > maxSaneUploadBytes {
		return nil, errUploadLimit
	}
	s := &Server{
		cfg:   opts.Config,
		store: opts.Store,
		auth:  opts.Auth,
		log:   opts.Logger,
	}
	s.http = &http.Server{
		Addr:              opts.Config.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: opts.Config.ReadHeaderTimeout,
		ReadTimeout:       opts.Config.ReadTimeout,
		WriteTimeout:      opts.Config.WriteTimeout,
		IdleTimeout:       opts.Config.IdleTimeout,
		MaxHeaderBytes:    opts.Config.MaxHeaderBytes,
		ErrorLog: slog.NewLogLogger(opts.Logger.Handler(),
			slog.LevelWarn),
	}
	return s, nil
}

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.http.Addr }

// MaxUploadBytes returns the configured per-file upload limit.
func (s *Server) MaxUploadBytes() int64 { return s.cfg.MaxUploadBytes }

// Listen binds the configured address. Splitting it from Serve lets a
// caller log between the two, so "listening" is only claimed once a
// socket actually exists and a bind failure is reported as such.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return ln, nil
}

// Serve accepts connections on ln until the server is shut down. It
// returns nil on a clean shutdown.
func (s *Server) Serve(ln net.Listener) error {
	if err := s.http.Serve(ln); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// Shutdown stops accepting connections and waits for in-flight requests to
// finish, up to the context's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// Handler returns the fully wrapped handler, exposed so tests can exercise
// routing without a listener.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Uploads are the only authenticated route. Both verbs are accepted
	// because PUT and POST are used interchangeably in the wild for
	// "replace this blob", and neither implies idempotency here: every
	// request mints a new random path.
	mux.Handle("POST /upload", s.authed(http.HandlerFunc(s.handleUpload)))
	mux.Handle("PUT /upload", s.authed(http.HandlerFunc(s.handleUpload)))

	// Downloads are open. A GET pattern also matches HEAD, which is what
	// lets a client check a size without pulling the whole object. Deletes
	// need a token and any valid one will do: knowledge of the unguessable
	// path is the capability, and the service keeps no per-object owner.
	mux.Handle("GET "+store.Rel+"/{dir}/{name}",
		http.HandlerFunc(s.handleDownload))
	mux.Handle("DELETE "+store.Rel+"/{dir}/{name}",
		s.authed(http.HandlerFunc(s.handleDelete)))

	for _, probe := range []string{"/healthz", "/livez", "/readyz"} {
		mux.Handle("GET "+probe, http.HandlerFunc(s.handleProbe))
	}

	// A method-agnostic catch-all so that an unknown path answers in JSON
	// with the same headers as everything else, rather than ServeMux's
	// bare text 404. handleNotFound restores the 405 distinction itself:
	// a known path with the wrong method still answers 405 with Allow.
	mux.HandleFunc("/", s.handleNotFound)

	return s.recover(s.securityHeaders(s.logRequests(mux)))
}
