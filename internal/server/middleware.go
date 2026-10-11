package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/mropc/http-flip/internal/auth"
)

// identityKey is the context key under which a verified upload identity is
// carried to the handler.
type identityKey struct{}

// identityFrom returns the verified caller, or the zero value if the request
// did not pass through the auth middleware.
func identityFrom(r *http.Request) auth.Identity {
	id, _ := r.Context().Value(identityKey{}).(auth.Identity)
	return id
}

// bearerToken extracts the token from the Authorization header.
//
// Only the header is consulted. A token supplied as a query parameter would be
// captured by every proxy access log and browser history between the client
// and this service, which is exactly the lifetime a credential must not have.
func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errMissingHeader
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", errBadScheme
	}
	// A client may pad; the token itself must not contain whitespace or it
	// is not the token that was issued.
	if token = strings.TrimSpace(token); token == "" {
		return "", errMissingHeader
	}
	return token, nil
}

var (
	errMissingHeader = errors.New("no Authorization header")
	errBadScheme     = errors.New("authorization scheme is not Bearer")
)

// authed wraps a handler with bearer authentication.
func (s *Server) authed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := bearerToken(r)
		if err != nil {
			s.reject(w, r, auth.Identity{}, err)
			return
		}
		id, err := s.auth.Authenticate(token)
		if err != nil {
			s.reject(w, r, auth.Identity{}, err)
			return
		}
		ctx := context.WithValue(r.Context(), identityKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// reject refuses an unauthenticated upload.
//
// An expired token is answered 403 rather than 401, because it is a different
// operational situation: the caller was valid and something changed, which is
// a rotation the operator did not finish or a clock the operator did not
// expect. Everything else is 401 with a challenge, per RFC 9110.
func (s *Server) reject(
	w http.ResponseWriter, r *http.Request, id auth.Identity, err error,
) {
	switch {
	case errors.Is(err, auth.ErrExpired):
		s.log.Warn("refused upload with expired token",
			"remote", remoteOf(r), "reason", err)
		s.writeJSON(w, http.StatusForbidden,
			errorBody{Error: "this token has expired"})
	case errors.Is(err, auth.ErrNoToken):
		s.log.Warn("refused upload with no token", "remote", remoteOf(r))
		w.Header().Set("WWW-Authenticate", bearerChallenge)
		s.writeJSON(w, http.StatusUnauthorized,
			errorBody{Error: "a bearer token is required"})
	default:
		// An unknown token may be a typo or may be a probe. Both are logged
		// at warn without the presented value, which is never worth
		// recording even in a log the operator trusts.
		s.log.Warn("refused upload with unrecognised token",
			"remote", remoteOf(r), "reason", err)
		w.Header().Set("WWW-Authenticate", bearerChallenge)
		s.writeJSON(w, http.StatusUnauthorized,
			errorBody{Error: "the bearer token is not recognised"})
	}
}

const bearerChallenge = `Bearer realm="httpflip"`

// errorBody is the shape of every non-success response.
type errorBody struct {
	Error string `json:"error"`
}

// writeJSON sends a JSON body. It deliberately sets Cache-Control: no-store,
// because response bodies here can contain freshly minted secret paths.
func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	blob, err := marshal(body)
	if err != nil {
		s.log.Error("cannot encode response", "err", err)
		blob = []byte(`{"error":"internal error"}`)
		status = http.StatusInternalServerError
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(blob); err != nil {
		s.log.Debug("cannot write response", "err", err)
	}
}

// recover turns a panic into a 500 rather than a dead process, and keeps the
// detail in the log instead of the response.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			s.log.Error("panic serving request",
				"method", r.Method, "path", r.URL.Path,
				"panic", v, "stack", string(debug.Stack()))
			s.writeJSON(w, http.StatusInternalServerError,
				errorBody{Error: "internal error"})
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders applies the headers that keep untrusted bytes inert.
//
// The service's whole purpose is to accept arbitrary content from one set of
// clients and hand it to another. These headers remove the browser's ability
// to interpret that content rather than merely display it.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// A download URL is itself the credential. Do not let a page that
		// embeds one leak it onward through the Referer header.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// JSON and probe responses are never rendered, but a default that
		// denies everything costs nothing; downloads set a stricter value
		// of their own. HSTS is honored on the Route's edge TLS and
		// ignored by plain-HTTP in-cluster probes.
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		h.Set("Strict-Transport-Security",
			"max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// recorder captures the status and byte count for logging. It ignores a
// second WriteHeader so that middleware above it cannot produce a duplicate,
// which net/http would reject.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (rec *recorder) WriteHeader(code int) {
	if rec.status != 0 {
		return
	}
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *recorder) Write(b []byte) (int, error) {
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	n, err := rec.ResponseWriter.Write(b)
	rec.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (rec *recorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// probePaths are logged at debug because an OpenShift probe fires every few
// seconds and would otherwise bury every real event.
var probePaths = map[string]bool{
	"/healthz": true,
	"/livez":   true,
	"/readyz":  true,
}

// logRequests emits one line per request.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		level := slog.LevelInfo
		if probePaths[r.URL.Path] {
			level = slog.LevelDebug
		}
		s.log.Log(r.Context(), level, "request",
			"method", r.Method,
			// The query string is deliberately omitted. This service has no
			// legitimate use for one, and logs outlive credential
			// rotation, so anything sensitive in it would be preserved.
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"duration", time.Since(start).Round(time.Microsecond),
			"remote", remoteOf(r),
			"client", clientOf(r),
		)
	})
}

// remoteOf is the address of the immediate peer, which behind a Route is the
// router rather than the caller.
func remoteOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientOf is the caller's address as the edge reports it.
//
// This is for the audit trail only and never for an access decision: the value
// is a header any client can set unless the proxy rewrites it, so trusting it
// to grant or deny access would be a mistake. The network-level subnet
// restriction is what actually bounds who can reach this service.
func clientOf(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if first, _, found := strings.Cut(fwd, ","); found {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(fwd)
	}
	return ""
}
