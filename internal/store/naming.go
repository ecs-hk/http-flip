package store

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
)

// base58 is the Bitcoin alphabet. It omits 0, O, I and l so that a name read
// aloud, retyped by hand or copied out of a log cannot be mangled into a
// different valid name.
const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

const base58Count = len(base58)

// base58Limit is the first byte value that would fold onto an alphabet entry
// twice, i.e. the point where b%base58Count stops being uniform. Bytes at or
// above it are discarded and redrawn instead of reduced, which avoids the
// modulo bias a naive reduction would introduce.
const base58Limit = 256 - (256 % base58Count)

const (
	// dirNameLen yields ~94 bits of entropy and shards the directory so a
	// busy store never accumulates one enormous directory entry.
	dirNameLen = 16
	// fileNameLen yields ~188 bits. Downloads are unauthenticated, so this
	// length is what stands in for an access control check.
	fileNameLen = 32

	// Rel is the URL prefix under which stored objects are served. It is
	// also the source of truth for the download route pattern.
	Rel = "/data"
)

// The patterns below are anchored with \A and \z rather than ^ and $ because
// Go's regexp treats $ as end-of-line-ish: it also matches before a trailing
// newline, which would let a crafted segment slip past. \z has no such
// alternate meaning.
//
// The character classes are exactly the base58 alphabet, which contains no
// '.', '/' or NUL. That is the entire traversal defence for downloads: a
// segment that matches cannot spell "..", so there is no denylist to keep
// updated and no encoding to normalise away first.
var (
	dirNamePattern  = regexp.MustCompile(`\A[1-9A-HJ-NP-Za-km-z]{16}\z`)
	fileNamePattern = regexp.MustCompile(`\A[1-9A-HJ-NP-Za-km-z]{32}\z`)
)

// randomBase58 returns n characters drawn uniformly from base58.
func randomBase58(n int) (string, error) {
	out := make([]byte, 0, n)
	// Over-read rather than looping one byte at a time so that the syscall
	// cost is amortised; the rejection rate is 24/256, so n bytes is ample
	// for any realistic n.
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, b := range buf {
			if int(b) >= base58Limit {
				continue
			}
			out = append(out, base58[int(b)%base58Count])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// IsObjectPath reports whether p has the shape of a stored object URL.
// It is the exported form of validatePath for handlers that need to tell a
// wrong method (405) from an unknown path (404) after routing.
func IsObjectPath(p string) bool {
	_, _, ok := validatePath(p)
	return ok
}

// validatePath splits rel into its two name components, reporting false for
// anything that is not exactly Rel/<dir>/<name>.
//
// r.URL.Path is already percent-decoded by net/http before a handler sees it,
// so this validates the decoded form, which is the form that reaches the
// filesystem. Decoding first and validating after is what makes the allowlist
// sufficient; validating the raw form would leave "%2e%2e%2f" to be worried
// about downstream.
func validatePath(rel string) (dir, name string, ok bool) {
	rest, found := strings.CutPrefix(rel, Rel+"/")
	if !found {
		return "", "", false
	}
	// Cut splits on the first separator only. A rel with extra separators
	// leaves a '/' inside name, which the pattern then rejects.
	dir, name, found = strings.Cut(rest, "/")
	if !found {
		return "", "", false
	}
	if !dirNamePattern.MatchString(dir) || !fileNamePattern.MatchString(name) {
		return "", "", false
	}
	return dir, name, true
}
