package auth

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	secretA = "a1b2c3d4e5f60718293a4b5c6d7e8f90" +
		"1a2b3c4d5e6f708192a3b4c5d6e7f809"
	secretB = "00112233445566778899aabbccddeeff" +
		"ffeeddccbbaa99887766554433221100"
	secretC = "deadbeefdeadbeefdeadbeefdeadbeef" +
		"cafebabecafebabecafebabecafebabe"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeTokens writes text to a file in a fresh temp dir and returns its path.
func writeTokens(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestParse(t *testing.T) {
	t.Parallel()
	text := strings.Join([]string{
		"# leading comment",
		"",
		"   ",
		"alpha  " + secretA + "  -",
		"\tbeta\t" + secretB + "\t2030-01-02T03:04:05Z",
		"gamma  " + secretC + "  -  # trailing comment is allowed",
	}, "\n")
	tokens, err := parse(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tokens) != 3 {
		t.Fatalf("len(tokens) = %d, want 3", len(tokens))
	}
	want := []string{"alpha", "beta", "gamma"}
	for i, w := range want {
		if tokens[i].name != w {
			t.Errorf("tokens[%d].name = %q, want %q",
				i, tokens[i].name, w)
		}
	}
	if !tokens[0].expires.IsZero() {
		t.Errorf("alpha expiry = %v, want zero", tokens[0].expires)
	}
	if tokens[1].expires.IsZero() {
		t.Error("beta expiry is zero, want a time")
	}
	if got := string(tokens[0].secret); got != secretA {
		t.Errorf("alpha secret = %s, want %s", got, secretA)
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		text string
	}{
		{"too few fields", "alpha  " + secretA},
		{"too many fields", "alpha  " + secretA + "  -  extra"},
		{"short secret", "alpha  abc123  -"},
		{"long secret", "alpha  " + secretA + "00  -"},
		{"non-hex secret", "alpha  " + strings.Repeat("z", 64) + "  -"},
		{"32 hex characters", "alpha  " + strings.Repeat("A", 32) + "  -"},
		{"expiry not rfc3339", "alpha  " + secretA + "  next tuesday"},
		{"expiry date only", "alpha  " + secretA + "  2030-01-02"},
		{"duplicate name",
			"alpha  " + secretA + "  -\nalpha  " + secretB + "  -"},
		{"empty name", "  " + secretA + "  -"},
		{"name with space is a field error",
			"alpha beta  " + secretA + "  -"},
		{"name with newline escape", "alpha\\n  " + secretA + "  -"},
		{"name with slash", "alpha/beta  " + secretA + "  -"},
		{"name too long", strings.Repeat("a", 65) + "  " + secretA + "  -"},
		{"64 non-hex characters", "alpha  " + strings.Repeat("Z", 64) + "  -"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parse(tc.text); err == nil {
				t.Errorf("parse(%q) succeeded, want error", tc.text)
			}
		})
	}
}

// A line an operator believed was live must never be silently dropped.
func TestParseRejectsOneBadLineAmongGoodOnes(t *testing.T) {
	t.Parallel()
	text := "good  " + secretA + "  -\n" +
		"bad  short  -\n" +
		"alsogood  " + secretB + "  -\n"
	if _, err := parse(text); err == nil {
		t.Fatal("parse succeeded with a malformed middle line, want error")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Path() != path {
		t.Errorf("Path = %q, want %q", a.Path(), path)
	}
	if a.Credentials() != 1 {
		t.Errorf("Credentials = %d, want 1", a.Credentials())
	}
}

// New must refuse to start rather than come up wide open.
func TestNewRefusesToStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		text string
	}{
		{"empty file", ""},
		{"comments only", "# nothing here\n# still nothing\n"},
		{"blank lines only", "\n\n  \n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeTokens(t, tc.text)
			if _, err := New(path, discardLogger()); err == nil {
				t.Error("New succeeded with no credentials, want error")
			}
		})
	}
}

func TestNewMissingFile(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := New(missing, discardLogger()); err == nil {
		t.Error("New succeeded on a missing file, want error")
	}
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\nbeta  "+secretB+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tests := []struct {
		name    string
		present string
		want    string
		wantErr error
	}{
		{"alpha", secretA, "alpha", nil},
		{"beta", secretB, "beta", nil},
		{"unknown", strings.Repeat("f", 64), "", ErrUnknownToken},
		{"prefix of alpha", secretA[:32], "", ErrUnknownToken},
		{"alpha plus a byte", secretA + "00", "", ErrUnknownToken},
		{"alpha with a byte changed", secretA[:63] + "f", "", ErrUnknownToken},
		{"uppercase hex is the same secret", strings.ToUpper(secretA),
			"alpha", nil},
		{"empty", "", "", ErrNoToken},
		{"whitespace", " " + secretA, "", ErrUnknownToken},
		{"wrong separator", "Bearer " + secretA, "", ErrUnknownToken},
		{"short", secretA[:10], "", ErrUnknownToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, err := a.Authenticate(tc.present)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if id.Token != tc.want {
				t.Errorf("Token = %q, want %q", id.Token, tc.want)
			}
		})
	}
}

func TestAuthenticateExpiry(t *testing.T) {
	t.Parallel()
	const past = "2020-01-01T00:00:00Z"
	const future = "2999-01-01T00:00:00Z"
	path := writeTokens(t, strings.Join([]string{
		"stale  " + secretA + "  " + past,
		"fresh  " + secretB + "  " + future,
		"eternal  " + secretC + "  -",
	}, "\n"))
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Authenticate(secretA); !errors.Is(err, ErrExpired) {
		t.Errorf("stale token err = %v, want ErrExpired", err)
	}
	if _, err := a.Authenticate(secretB); err != nil {
		t.Errorf("fresh token err = %v, want nil", err)
	}
	if _, err := a.Authenticate(secretC); err != nil {
		t.Errorf("eternal token err = %v, want nil", err)
	}
}

// A duplicated secret with one live entry must still authenticate: expiry
// is per-match, and success needs only one active match.
func TestDuplicateSecretMixedExpiry(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, strings.Join([]string{
		"stale  " + secretA + "  2020-01-01T00:00:00Z",
		"live  " + secretA + "  -",
	}, "\n"))
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Authenticate(secretA); err != nil {
		t.Errorf("duplicated secret with a live entry err = %v, want nil",
			err)
	}
	doubled := writeTokens(t, strings.Join([]string{
		"stale1  " + secretA + "  2020-01-01T00:00:00Z",
		"stale2  " + secretA + "  2021-01-01T00:00:00Z",
	}, "\n"))
	b, err := New(doubled, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := b.Authenticate(secretA); !errors.Is(err, ErrExpired) {
		t.Errorf("all-expired duplicate err = %v, want ErrExpired", err)
	}
}

// Expiry is evaluated at authentication time, not at load time, so a token
// cannot be immortalised by a pod that happened to start before it lapsed.
func TestExpiryAdvancesWithClock(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "soon  "+secretA+"  2030-01-01T00:00:00Z\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := time.Date(2029, 12, 31, 23, 0, 0, 0, time.UTC)
	after := time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC)

	a.now = func() time.Time { return before }
	if _, err := a.Authenticate(secretA); err != nil {
		t.Errorf("before expiry err = %v, want nil", err)
	}
	a.now = func() time.Time { return after }
	if _, err := a.Authenticate(secretA); !errors.Is(err, ErrExpired) {
		t.Errorf("after expiry err = %v, want ErrExpired", err)
	}
}

// An added token must take effect without a restart, which is the entire
// point of hot reload.
func TestHotReloadPicksUpAdditions(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Authenticate(secretB); !errors.Is(
		err, ErrUnknownToken,
	) {
		t.Fatalf("beta unknown before it was added: %v", err)
	}

	rewrite(t, path, "alpha  "+secretA+"  -\nbeta  "+secretB+"  -\n")

	id, err := a.Authenticate(secretB)
	if err != nil {
		t.Fatalf("beta after reload: %v", err)
	}
	if id.Token != "beta" {
		t.Errorf("Token = %q, want beta", id.Token)
	}
	if a.Credentials() != 2 {
		t.Errorf("Credentials = %d, want 2", a.Credentials())
	}
}

func TestHotReloadHonoursRevocation(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\nbeta  "+secretB+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Authenticate(secretA); err != nil {
		t.Fatalf("alpha before revocation: %v", err)
	}

	rewrite(t, path, "beta  "+secretB+"  -\n")

	if _, err := a.Authenticate(secretA); !errors.Is(
		err, ErrUnknownToken,
	) {
		t.Errorf("alpha after revocation err = %v, want ErrUnknownToken", err)
	}
	if _, err := a.Authenticate(secretB); err != nil {
		t.Errorf("beta should still work: %v", err)
	}
}

// A malformed edit must not lock out every client, and must not silently
// disable authentication either: the previous set stays in force.
func TestHotReloadKeepsLastGoodOnParseError(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rewrite(t, path, "alpha  not-hex  -\n")

	if _, err := a.Authenticate(secretA); err != nil {
		t.Errorf("alpha after bad edit err = %v, want nil", err)
	}
}

func TestHotReloadIgnoresZeroCredentialFile(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rewrite(t, path, "# emptied out\n")

	if _, err := a.Authenticate(secretA); err != nil {
		t.Errorf("alpha after emptying err = %v, want nil", err)
	}
}

func TestReloadSurvivesVanishedFile(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := a.Authenticate(secretA); err != nil {
		t.Errorf("err = %v, want cached credentials to keep working", err)
	}
}

// Reload happens on the request path, so it must be race-free.
func TestConcurrentAuthenticateDuringReloads(t *testing.T) {
	t.Parallel()
	path := writeTokens(t, "alpha  "+secretA+"  -\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)

	// One writer churning the file underneath, alternating between two valid
	// sets so the published pointer really is replaced as readers run.
	wg.Add(1)
	go func() {
		defer wg.Done()
		withBeta := "alpha  " + secretA + "  -\nbeta  " + secretB + "  -\n"
		withoutBeta := "alpha  " + secretA + "  -\n"
		for i := range 50 {
			text := []byte(withoutBeta)
			if i%2 == 0 {
				text = []byte(withBeta)
			}
			if err := os.WriteFile(path, text, 0o600); err != nil {
				errs <- fmt.Errorf("write: %w", err)
				return
			}
		}
	}()

	// Readers hammering the authentication path while it churns.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if _, err := a.Authenticate(secretA); err != nil {
					errs <- fmt.Errorf("authenticate: %w", err)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// The comparison must not short-circuit, so a hit has to cost the same as a
// miss. Timing cannot be asserted reliably here; what this pins is that a
// large credential set is walked correctly for both a first-position hit and
// a miss. The early-exit rule itself is documented on Authenticate.
func TestAuthenticateAgainstManyCredentials(t *testing.T) {
	t.Parallel()
	// Many credentials, so a first-match early return would save most of the
	// work on a hit and almost none on a miss.
	var lines []string
	for i := range 64 {
		lines = append(lines, nameFor(i)+"  "+secretFor(i)+"  -")
	}
	path := writeTokens(t, strings.Join(lines, "\n")+"\n")
	a, err := New(path, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Credentials() != 64 {
		t.Fatalf("Credentials = %d, want 64", a.Credentials())
	}
	// First credential, so a hit would skip the remaining 63.
	if _, err := a.Authenticate(secretFor(0)); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := a.Authenticate(strings.Repeat("a", 64)); !errors.Is(
		err, ErrUnknownToken,
	) {
		t.Fatalf("miss err = %v, want ErrUnknownToken", err)
	}
}

func nameFor(i int) string {
	return "token-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
}

func secretFor(i int) string {
	return strings.Repeat(string(rune('0'+i%10)), 63) +
		string(rune('0'+(i+1)%10))
}

// rewrite replaces a file's contents. Reload re-reads the file on every
// authenticated request, so no timestamp dance is needed to make it notice.
func rewrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
