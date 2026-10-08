// Package auth verifies bearer tokens against a mounted file of named
// credentials.
//
// Each presented token is compared against every configured credential without
// early exit, so response timing does not reveal how much of it was correct.
// The file is re-read on every upload, which lets an operator rotate or revoke
// a token by editing a Secret, with no pod restart.
package auth

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// secretLen is the required secret length in bytes, and secretHexLen its hex
// encoding. 32 bytes is not a floor to be argued with: a shorter secret would
// be guessable in principle, and an operator who picks one picks it once and
// forgets it, so there would be no second chance to notice.
const (
	secretLen    = 32
	secretHexLen = 2 * secretLen
)

// tokenNamePattern constrains credential names so that a name can be written
// to a log line verbatim. An unvalidated name is an injection vector into the
// audit trail, which is the one thing an operator relies on when working out
// who uploaded what.
var tokenNamePattern = regexp.MustCompile(`\A[A-Za-z0-9._-]{1,64}\z`)

// Authentication outcomes. These are distinct because an operator debugging a
// rejection needs to tell "you rotated me out" from "someone is guessing".
var (
	// ErrNoToken means no usable credential was presented.
	ErrNoToken = errors.New("no bearer token presented")
	// ErrUnknownToken means the presented token matched nothing.
	ErrUnknownToken = errors.New("bearer token not recognised")
	// ErrExpired means the token matched a credential whose expiry has
	// passed: the caller was valid once and is not now.
	ErrExpired = errors.New("bearer token expired")
)

// Identity is the outcome of a successful authentication.
type Identity struct {
	// Token is the credential's name, safe to log. The secret itself never
	// leaves the process.
	Token string
}

// token is one parsed credential.
type token struct {
	name string
	// secret is the token exactly as an operator wrote it, compared
	// verbatim against whatever the client presented. Storing the hex text
	// rather than the decoded bytes means the thing compared is the thing in
	// the file, so there is no second representation to disagree with it.
	// parse still decodes, to confirm the value is well formed and exactly
	// secretLen bytes.
	secret  []byte
	expires time.Time // zero means no expiry
}

// active reports whether the token may still be used at time now.
func (t token) active(now time.Time) bool {
	return t.expires.IsZero() || now.Before(t.expires)
}

// set is an immutable collection of credentials. It is replaced wholesale
// on reload and never mutated, which is what makes publishing one to
// lock-free readers safe.
type set struct {
	tokens []token
}

// Authenticator verifies bearer tokens against a file, reloading it when the
// file changes. It is safe for concurrent use. The zero value is not usable;
// call New.
type Authenticator struct {
	path string
	log  *slog.Logger
	// now is swappable so expiry can be tested without sleeping.
	now func() time.Time
	cur atomic.Pointer[set]
}

// New loads path and returns an Authenticator.
//
// It fails if the file cannot be read, is malformed, or yields no usable
// credentials. That strictness is the point: a service that starts with an
// empty token set would silently accept every upload, turning a broken volume
// mount into an open endpoint.
func New(path string, log *slog.Logger) (*Authenticator, error) {
	tokens, err := load(path)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("token file %q contains no credentials", path)
	}
	a := &Authenticator{path: path, log: log, now: time.Now}
	a.cur.Store(&set{tokens: tokens})
	return a, nil
}

// Path returns the token file being watched.
func (a *Authenticator) Path() string { return a.path }

// Credentials reports how many credentials are currently loaded.
func (a *Authenticator) Credentials() int {
	return len(a.cur.Load().tokens)
}

// Authenticate reports whether presented is a currently valid credential, and
// returns its name on success.
//
// Every configured credential is compared even after a match, because
// returning early would make the work done depend on the answer and leak the
// length of a matching prefix through timing.
func (a *Authenticator) Authenticate(presented string) (Identity, error) {
	s := a.reload()
	if presented == "" {
		return Identity{}, ErrNoToken
	}
	now := a.now()
	// Secrets are hex and therefore case-insensitive; normalize so an
	// operator pasting uppercase does not get a mysterious rejection.
	guess := []byte(strings.ToLower(presented))

	var (
		activeName string
		haveActive bool
		haveMatch  bool
	)
	for _, t := range s.tokens {
		// ConstantTimeCompare returns 1 on a match and 0 otherwise, in time
		// that depends only on the lengths of its arguments.
		if subtle.ConstantTimeCompare(guess, t.secret) == 1 {
			haveMatch = true
			if t.active(now) {
				activeName, haveActive = t.name, true
			}
		}
	}
	switch {
	case haveActive:
		return Identity{Token: activeName}, nil
	case haveMatch:
		return Identity{}, ErrExpired
	default:
		return Identity{}, ErrUnknownToken
	}
}

// reload returns the current credential set, re-reading the file first.
//
// Uploads are infrequent and the file is tiny, so the file is re-read on
// every call rather than keyed off modTime+size: a same-size edit inside one
// timestamp tick can never be missed, and there is no stat/read race to
// reason about. A reload that fails is logged and ignored, leaving the
// previous set in force. That is a deliberate trade: an operator typo should
// degrade to a visible error rather than an outage, at the cost of a
// malformed file revoking nothing until it is corrected.
func (a *Authenticator) reload() *set {
	cur := a.cur.Load()
	tokens, err := load(a.path)
	if err != nil {
		a.log.Error("cannot reload token file; serving cached credentials",
			"path", a.path, "err", err, "cached", len(cur.tokens))
		return cur
	}
	if len(tokens) == 0 {
		a.log.Error("token file parsed to zero credentials; "+
			"serving cached ones",
			"path", a.path, "cached", len(cur.tokens))
		return cur
	}
	if tokensEqual(cur.tokens, tokens) {
		return cur
	}
	a.log.Info("reloaded token file", "path", a.path, "credentials",
		len(tokens))
	fresh := &set{tokens: tokens}
	a.cur.Store(fresh)
	return fresh
}

// tokensEqual reports whether two credential sets hold the same entries,
// so an unchanged file does not churn the log or the stored pointer.
func tokensEqual(a, b []token) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].name != b[i].name ||
			!a[i].expires.Equal(b[i].expires) ||
			subtle.ConstantTimeCompare(a[i].secret, b[i].secret) != 1 {
			return false
		}
	}
	return true
}

// load reads and parses the token file.
func load(path string) ([]token, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	tokens, err := parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse token file %s: %w", path, err)
	}
	return tokens, nil
}

// parse turns token file text into credentials.
//
// The format is one credential per line, three whitespace-separated fields,
// with blank lines and '#' comments ignored:
//
//	name  <hex secret>  <RFC3339 expiry or "-">
//
// A malformed line is an error rather than a skip. Silently ignoring a line
// an operator believed was live is how a token ends up looking configured
// while nothing enforces it.
func parse(text string) ([]token, error) {
	var tokens []token
	seen := make(map[string]bool)
	for i, line := range strings.Split(text, "\n") {
		num := i + 1
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			// A '#' starts a comment anywhere on the line. Stripping it
			// before splitting fields is unambiguous: no field can contain
			// one, since the name pattern excludes it and a secret is hex.
			// Without this an operator writing a trailing comment gets a
			// baffling field-count error.
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: want 3 fields, got %d",
				num, len(fields))
		}
		name, hexSecret, expiry := fields[0], fields[1], fields[2]
		if !tokenNamePattern.MatchString(name) {
			return nil, fmt.Errorf("line %d: invalid token name %q",
				num, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("line %d: duplicate token name %q",
				num, name)
		}
		seen[name] = true

		if len(hexSecret) != secretHexLen {
			return nil, fmt.Errorf("line %d: secret must be %d hex "+
				"characters, got %d", num, secretHexLen, len(hexSecret))
		}
		// Hex is case-insensitive, so store the lowercase form and compare
		// against a lowercased presentation: an uppercase paste is the
		// same secret, not a different one.
		hexSecret = strings.ToLower(hexSecret)
		if _, err := hex.DecodeString(hexSecret); err != nil {
			return nil, fmt.Errorf("line %d: secret is not hex: %w",
				num, err)
		}
		expires, err := parseExpiry(num, expiry)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token{
			name:    name,
			secret:  []byte(hexSecret),
			expires: expires,
		})
	}
	return tokens, nil
}

// parseExpiry reads the third field, where "-" means no expiry.
func parseExpiry(line int, field string) (time.Time, error) {
	if field == "-" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, field)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"line %d: expiry %q is not RFC3339: %w", line, field, err)
	}
	return t, nil
}
