package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mropc/http-flip/internal/auth"
	"github.com/mropc/http-flip/internal/store"
)

const liveSecret = "a1b2c3d4e5f60718293a4b5c6d7e8f90" +
	"1a2b3c4d5e6f708192a3b4c5d6e7f809"
const staleSecret = "00112233445566778899aabbccddeeff" +
	"ffeeddccbbaa99887766554433221100"

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// harness is a fully wired Server over a temporary store, reachable through
// httptest without binding a port.
type harness struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	store   *store.Store
}

type option func(*Config)

// withLimit shrinks the upload limit so that oversized cases need only a small
// payload.
func withLimit(n int64) option {
	return func(c *Config) { c.MaxUploadBytes = n }
}

func newHarness(t *testing.T, tokens string, opts ...option) *harness {
	t.Helper()
	if tokens == "" {
		tokens = "live  " + liveSecret + "  -\n"
	}
	tokenPath := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(tokenPath, []byte(tokens), 0o600); err != nil {
		t.Fatalf("write tokens: %v", err)
	}
	authn, err := auth.New(tokenPath, discardLogger())
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	st, err := store.New(filepath.Join(t.TempDir(), "data"), discardLogger())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store close: %v", err)
		}
	})

	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	srv, err := New(Options{Config: cfg, Store: st, Auth: authn,
		Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{t: t, srv: srv, handler: srv.Handler(), store: st}
}

func (h *harness) do(
	method, target string, body io.Reader, hdrs map[string]string,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

type partSpec struct {
	filename    string
	contentType string
	content     string
}

// multipartBody builds a multipart body from the given parts.
func multipartBody(t *testing.T, parts []partSpec) (io.Reader, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	for _, p := range parts {
		hdr := textproto.MIMEHeader{}
		if p.filename == "" {
			hdr.Set("Content-Disposition", `form-data; name="field"`)
		} else {
			hdr.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name="file"; filename=%q`,
					p.filename))
			if p.contentType != "" {
				hdr.Set("Content-Type", p.contentType)
			}
		}
		w, err := mw.CreatePart(hdr)
		if err != nil {
			t.Fatalf("CreatePart: %v", err)
		}
		if _, err := io.WriteString(w, p.content); err != nil {
			t.Fatalf("write part: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return buf, mw.FormDataContentType()
}

type uploadBody struct {
	Path        string `json:"path"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	UploadedBy  string `json:"uploaded_by"`
}

// decodeUpload must be called from the test goroutine, never a spawned one,
// because it may call t.Fatalf.
func decodeUpload(t *testing.T, rec *httptest.ResponseRecorder) uploadBody {
	t.Helper()
	var out uploadBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func (h *harness) upload(
	token, filename, contentType, content string,
) *httptest.ResponseRecorder {
	body, ctype := multipartBody(h.t, []partSpec{
		{filename, contentType, content},
	})
	return h.do(http.MethodPost, "/upload", body, map[string]string{
		"Content-Type":  ctype,
		"Authorization": "Bearer " + token,
	})
}

func TestUploadHappyPath(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	const content = "the quick brown fox"
	rec := h.upload(liveSecret, "report.pdf", "application/pdf", content)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	got := decodeUpload(t, rec)
	if !strings.HasPrefix(got.Path, store.Rel+"/") {
		t.Errorf("path = %q, want prefix %q", got.Path, store.Rel)
	}
	if got.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", got.Size, len(content))
	}
	if got.Filename != "report.pdf" {
		t.Errorf("filename = %q, want report.pdf", got.Filename)
	}
	if got.ContentType != "application/pdf" {
		t.Errorf("content_type = %q, want application/pdf", got.ContentType)
	}
	if got.UploadedBy != "live" {
		t.Errorf("uploaded_by = %q, want live", got.UploadedBy)
	}
	if len(got.SHA256) != 64 {
		t.Errorf("sha256 = %q, want 64 hex chars", got.SHA256)
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" ||
		!strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want JSON", ct)
	}
}

func TestUploadThenDownload(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	const content = "round trip payload"
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain", content))

	rec := h.do(http.MethodGet, up.Path, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != content {
		t.Errorf("body = %q, want %q", rec.Body.String(), content)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(
		cd, "a.txt") {
		t.Errorf("content-disposition = %q, want it to name a.txt", cd)
	}
}

func TestDownloadNeedsNoToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain", "x"))
	// No Authorization header at all, and none is required.
	if rec := h.do(http.MethodGet, up.Path, nil, nil); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 without a token", rec.Code)
	}
}

func TestProbesAreUnauthenticated(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	for _, p := range []string{"/healthz", "/livez", "/readyz"} {
		if rec := h.do(http.MethodGet, p, nil, nil); rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", p, rec.Code)
		}
	}
}

func TestUploadRequiresToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	tests := []struct {
		name    string
		hdr     string
		want    int
		hasChal bool
	}{
		{"no header", "", http.StatusUnauthorized, true},
		{"wrong token", "Bearer " + strings.Repeat("0", 64),
			http.StatusUnauthorized, true},
		{"empty bearer", "Bearer ", http.StatusUnauthorized, true},
		{"basic scheme", "Basic " + liveSecret,
			http.StatusUnauthorized, true},
		{"bare token, no scheme", liveSecret,
			http.StatusUnauthorized, true},
		{"scheme is case insensitive", "bearer " + liveSecret,
			http.StatusCreated, false},
		{"scheme padded", "Bearer   " + liveSecret,
			http.StatusCreated, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Built per subtest: a bytes.Buffer is not safe to share.
			body, ctype := multipartBody(t, []partSpec{
				{"a.txt", "text/plain", "x"},
			})
			hdrs := map[string]string{"Content-Type": ctype}
			if tc.hdr != "" {
				hdrs["Authorization"] = tc.hdr
			}
			rec := h.do(http.MethodPost, "/upload", body, hdrs)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body %s",
					rec.Code, tc.want, rec.Body)
			}
			gotChal := rec.Header().Get("WWW-Authenticate") != ""
			if gotChal != tc.hasChal {
				t.Errorf("WWW-Authenticate present = %v, want %v",
					gotChal, tc.hasChal)
			}
		})
	}
}

// An expired token is a different operational problem from a wrong one.
func TestExpiredTokenIsForbidden(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "stale  "+staleSecret+"  2020-01-01T00:00:00Z\n")
	body, ctype := multipartBody(t, []partSpec{
		{"a.txt", "text/plain", "x"},
	})
	rec := h.do(http.MethodPost, "/upload", body, map[string]string{
		"Content-Type":  ctype,
		"Authorization": "Bearer " + staleSecret,
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Error("a 403 should not carry a challenge")
	}
}

// A credential in the query string is a leak waiting to happen.
func TestTokenInQueryStringIsIgnored(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	body, ctype := multipartBody(t, []partSpec{
		{"a.txt", "text/plain", "x"},
	})
	rec := h.do(http.MethodPost, "/upload?token="+liveSecret, body,
		map[string]string{"Content-Type": ctype})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body %s", rec.Code, rec.Body)
	}
}

func TestUploadTooLarge(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "", withLimit(64))
	rec := h.upload(liveSecret, "big.bin", "application/octet-stream",
		strings.Repeat("x", 128))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body %s", rec.Code, rec.Body)
	}
	// Nothing at all may be left behind by a rejected upload.
	entries, err := os.ReadDir(h.store.Dir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("store has %d entries after a rejected upload", len(entries))
	}
}

// A body exactly at the limit must succeed: multipart framing must not be
// mistaken for payload.
func TestUploadAtExactLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "", withLimit(1024))
	rec := h.upload(liveSecret, "a.bin", "",
		strings.Repeat("x", 1024))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	if got := decodeUpload(t, rec).Size; got != 1024 {
		t.Errorf("size = %d, want 1024", got)
	}
}

func TestUploadRejectsWrongContentType(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	tests := []struct{ name, ct string }{
		{"json", "application/json"},
		{"octet stream", "application/octet-stream"},
		{"empty", ""},
		{"garbage", "not a media type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := h.do(http.MethodPost, "/upload", strings.NewReader("x"),
				map[string]string{"Content-Type": tc.ct,
					"Authorization": "Bearer " + liveSecret})
			if rec.Code != http.StatusUnsupportedMediaType {
				t.Errorf("status = %d, want 415", rec.Code)
			}
		})
	}
}

// A declared multipart body with no boundary is unparseable rather than of
// the wrong media type, so it is a bad request rather than an unsupported one.
func TestUploadMultipartWithoutBoundary(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	rec := h.do(http.MethodPost, "/upload", strings.NewReader("x"),
		map[string]string{"Content-Type": "multipart/form-data",
			"Authorization": "Bearer " + liveSecret})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body)
	}
}

func TestUploadWithoutFilePart(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	if err := mw.WriteField("just", "a field"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rec := h.do(http.MethodPost, "/upload", buf, map[string]string{
		"Content-Type":  mw.FormDataContentType(),
		"Authorization": "Bearer " + liveSecret,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body)
	}
}

func TestUploadWithTwoFileParts(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	body, ctype := multipartBody(t, []partSpec{
		{"a.txt", "text/plain", "first"},
		{"b.txt", "text/plain", "second"},
	})
	rec := h.do(http.MethodPost, "/upload", body, map[string]string{
		"Content-Type":  ctype,
		"Authorization": "Bearer " + liveSecret,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body)
	}
	// The already-stored first part must be cleaned up: a rejected upload
	// leaves nothing behind, reachable or not.
	entries, err := os.ReadDir(h.store.Dir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("store has %d entries after a rejected multi-part upload",
			len(entries))
	}
}

func TestUploadEmptyFile(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	rec := h.upload(liveSecret, "empty.txt", "text/plain", "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	if got := decodeUpload(t, rec).Size; got != 0 {
		t.Errorf("size = %d, want 0", got)
	}
}

// Untrusted bytes must never be described in a way a browser would act on.
func TestDownloadHeadersNeutraliseContent(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	const html = `<script>alert(document.cookie)</script>`
	up := decodeUpload(t, h.upload(liveSecret, "x.html", "text/html", html))
	rec := h.do(http.MethodGet, up.Path, nil, nil)

	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("content-type = %q, want application/octet-stream", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("nosniff = %q, want nosniff", got)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment") {
		t.Errorf("content-disposition = %q, want attachment", cd)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(
		got, "sandbox") {
		t.Errorf("csp = %q, want it to contain sandbox", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("referrer-policy = %q, want no-referrer", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("cache-control = %q, want no-store", got)
	}
	if rec.Body.String() != html {
		t.Errorf("body was altered: %q", rec.Body.String())
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Content-Security-Policy":      "default-src 'none'; sandbox",
		"Strict-Transport-Security":    "max-age=63072000; includeSubDomains",
	}
	for _, target := range []string{"/healthz", "/nope", "/upload"} {
		rec := h.do(http.MethodGet, target, nil, nil)
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", target, k, got, v)
			}
		}
	}
}

// A client-supplied filename lands in a response header on download, where CR
// or LF would let an uploader inject headers into a third party's response.
func TestContentDispositionStopsHeaderInjection(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"a\r\nX-Injected: 1",
		"a\nX-Injected: 1",
		"a\rX: 1",
		"a\x00b",
		`a"b`,
		`a\b`,
	} {
		got := contentDisposition(in)
		if !strings.HasPrefix(got, "attachment") {
			t.Errorf("contentDisposition(%q) = %q, want attachment", in, got)
		}
		for _, bad := range []string{"\r", "\n", "\x00", "\\"} {
			if strings.Contains(got, bad) {
				t.Errorf("contentDisposition(%q) = %q, must not contain %q",
					in, got, bad)
			}
		}
		// Exactly the two delimiters of the quoted-string form.
		if n := strings.Count(got, `"`); n != 2 {
			t.Errorf("contentDisposition(%q) = %q, has %d quotes",
				in, got, n)
		}
	}
}

func TestContentDispositionPreservesUnicode(t *testing.T) {
	t.Parallel()
	got := contentDisposition("Ünïcödé réport — 2026.pdf")
	if !strings.Contains(got, "filename*=UTF-8''") {
		t.Errorf("got %q, want a filename* form", got)
	}
	if !strings.Contains(got, "%C3%9C") {
		t.Errorf("got %q, want percent-encoded UTF-8", got)
	}
	if !strings.Contains(got, `filename="`) {
		t.Errorf("got %q, want an ASCII fallback too", got)
	}
}

func TestContentDispositionFallsBack(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "   ", ".", "..", "\r\n"} {
		got := contentDisposition(in)
		if !strings.Contains(got, `filename="download"`) {
			t.Errorf("contentDisposition(%q) = %q, want the fallback",
				in, got)
		}
	}
}

// The end-to-end path: a hostile filename must not become a hostile header.
func TestHostileFilenameSurvivesRoundTrip(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	hostile := "evil\r\nSet-Cookie: session=stolen\r\n\r\n<html>"
	up := decodeUpload(t, h.upload(liveSecret, hostile, "text/html", "x"))
	rec := h.do(http.MethodGet, up.Path, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if v := rec.Header().Get("Set-Cookie"); v != "" {
		t.Errorf("hostile filename injected Set-Cookie: %q", v)
	}
}

// Malformed and absent paths must be indistinguishable from the outside.
//
// Paths needing cleaning are answered by ServeMux with a redirect to their
// cleaned form. That is safe and intentional: the cleaned form is what the
// client would have had to request anyway, and it reaches no handler here. The
// invariant under test is therefore that no attempt ever serves bytes, and
// that anything ServeMux does not redirect is a plain 404.
func TestDownloadTraversalAttempts(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	const dir = "XcFCyemkp1GeXYZq"
	const name = "9mZqT4rKxW2vNbHdY7pLcAeFjGhQwErT"

	// A real object, so that a 404 cannot be explained by an empty store.
	up := decodeUpload(t, h.upload(liveSecret, "ok.txt", "text/plain", "x"))
	if rec := h.do(http.MethodGet, up.Path, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("control download failed: %d", rec.Code)
	}

	notFound := []string{
		"/data/..%2f..%2fetc%2fpasswd",
		"/data/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/data/" + dir + "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/etc/passwd",
		"/data",
		"/data/",
		"/data/" + dir,
		"/data/" + dir + "/",
		"/data/" + dir + "/" + name + "/",
		"/data/" + dir + "/" + name + "/x",
		"/data/" + strings.Repeat("a", 15) + "/" + name,
		"/data/" + dir + "/" + strings.Repeat("a", 31),
		"/data/" + dir + "/" + name + "Z",
		"/data/" + dir + "/" + name + "extra",
		"/data/" + strings.Repeat(".", 16) + "/" + name,
		// The sidecar is not an object.
		"/data/" + dir + "/" + name + ".meta",
		// Control characters, as an attacker must actually send them: a raw
		// NUL or newline cannot appear in a request line at all.
		"/data/" + dir + "/" + name + "%00",
		"/data/" + dir + "/" + name + "%0a",
		"/data/" + dir + "/" + name + "%0d%0aX-Injected:%201",
		"/data/%00/" + name,
	}
	for _, target := range notFound {
		rec := h.do(http.MethodGet, target, nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %q status = %d, want 404; body %s",
				target, rec.Code, rec.Body)
		}
		assertNoLeak(t, target, rec)
	}

	// These are redirected to their cleaned form, which then 404s. What
	// matters is that the redirect itself serves nothing.
	redirected := []string{
		"/data/../../etc/passwd",
		"/data/" + dir + "/../../etc/passwd",
		"/data/" + dir + "/" + name + "/../../../../etc/passwd",
		"/data/" + dir[:15] + "/../" + name,
		"/data/" + dir + "//" + name,
		"/data/./" + dir + "/" + name,
		"/data//" + dir + "/" + name,
	}
	for _, target := range redirected {
		rec := h.do(http.MethodGet, target, nil, nil)
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("GET %q status = %d, want 301", target, rec.Code)
		}
		if loc := rec.Header().Get("Location"); strings.Contains(
			loc, "..") {
			t.Errorf("GET %q redirected to %q, which still has ..",
				target, loc)
		}
		assertNoLeak(t, target, rec)
	}
}

// assertNoLeak checks that a response for a hostile path served no filesystem
// content, whatever its status.
func assertNoLeak(t *testing.T, target string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code == http.StatusOK {
		t.Errorf("GET %q was served with 200", target)
	}
	for _, marker := range []string{"root:", "/bin/", "no such file"} {
		if strings.Contains(rec.Body.String(), marker) {
			t.Errorf("GET %q leaked %q: %s", target, marker, rec.Body)
		}
	}
}

func TestDownloadNotFound(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	rec := h.do(http.MethodGet,
		"/data/XcFCyemkp1GeXYZq/9mZqT4rKxW2vNbHdY7pLcAeFjGhQwErT",
		nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHeadDownload(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain", "bytes"))
	rec := h.do(http.MethodHead, up.Path, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD returned a body of %d bytes", rec.Body.Len())
	}
}

func TestRangeRequest(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain",
		strings.Repeat("0123456789", 5)))
	rec := h.do(http.MethodGet, up.Path, nil,
		map[string]string{"Range": "bytes=5-9"})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	if rec.Body.String() != "56789" {
		t.Errorf("body = %q, want 56789", rec.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain", "x"))
	// POST is never valid for an object path; DELETE now is (authenticated),
	// so exercise the 405 with POST.
	rec := h.do(http.MethodPost, up.Path, nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") == "" {
		t.Error("405 should carry an Allow header")
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Errorf("405 body is not JSON: %s", rec.Body)
	}
}

func TestUnknownPathMethodsAreJSON404(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	for _, m := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch,
	} {
		rec := h.do(m, "/nope", nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s /nope status = %d, want 404", m, rec.Code)
		}
		var body errorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("%s /nope body is not JSON: %s", m, rec.Body)
		}
	}
}

func TestDeleteRoundTrip(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain",
		"to delete"))

	rec := h.do(http.MethodDelete, up.Path, nil, map[string]string{
		"Authorization": "Bearer " + liveSecret,
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204; body %s",
			rec.Code, rec.Body)
	}
	if got := h.do(http.MethodGet, up.Path, nil, nil); got.Code !=
		http.StatusNotFound {
		t.Errorf("GET after DELETE = %d, want 404", got.Code)
	}
	again := h.do(http.MethodDelete, up.Path, nil, map[string]string{
		"Authorization": "Bearer " + liveSecret,
	})
	if again.Code != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", again.Code)
	}
	entries, err := os.ReadDir(h.store.Dir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("store has %d entries after DELETE", len(entries))
	}
}

func TestDeleteRequiresToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain", "x"))
	if rec := h.do(http.MethodDelete, up.Path, nil, nil); rec.Code !=
		http.StatusUnauthorized {
		t.Errorf("DELETE without token = %d, want 401", rec.Code)
	}
	rec := h.do(http.MethodDelete, "/data/XcFCyemkp1GeXYZq/"+
		"9mZqT4rKxW2vNbHdY7pLcAeFjGhQwErT", nil, map[string]string{
		"Authorization": "Bearer " + liveSecret,
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("DELETE missing object = %d, want 404", rec.Code)
	}
}

// A volume failure during a delete is a 500, not a 404: the object
// is still there, and the response must not claim otherwise.
func TestDeleteStorageFailureIsServerError(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	h := newHarness(t, "")
	up := decodeUpload(t, h.upload(liveSecret, "a.txt", "text/plain", "x"))

	// The object's directory is the first segment of its path.
	// Removing an entry needs write permission on it; take that
	// away to make the remove fail.
	rel := strings.TrimPrefix(up.Path, store.Rel+"/")
	objDir := filepath.Join(h.store.Dir(), strings.SplitN(rel, "/", 2)[0])
	if err := os.Chmod(objDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(objDir, 0o770) }()

	rec := h.do(http.MethodDelete, up.Path, nil, map[string]string{
		"Authorization": "Bearer " + liveSecret,
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE status = %d, want 500; body %s",
			rec.Code, rec.Body)
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Errorf("500 body is not JSON: %s", rec.Body)
	}
	// The object survived.
	if got := h.do(http.MethodGet, up.Path, nil, nil); got.Code !=
		http.StatusOK {
		t.Errorf("GET after a failed delete = %d, want 200", got.Code)
	}
}

func TestPutUploadIsAccepted(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	body, ctype := multipartBody(t, []partSpec{
		{"a.txt", "text/plain", "via put"},
	})
	rec := h.do(http.MethodPut, "/upload", body, map[string]string{
		"Content-Type":  ctype,
		"Authorization": "Bearer " + liveSecret,
	})
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
}

func TestUnknownPathIsJSON404(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	for _, p := range []string{"/", "/admin", "/data", "/upload/extra"} {
		rec := h.do(http.MethodGet, p, nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %q status = %d, want 404", p, rec.Code)
		}
		var body errorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("GET %q body is not JSON: %s", p, rec.Body)
		}
	}
}

func TestRecoverMiddleware(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	const secretDetail = "top-secret-internal-detail"
	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(secretDetail)
	})
	rec := httptest.NewRecorder()
	h.srv.recover(panicky).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secretDetail) {
		t.Errorf("panic detail leaked to the client: %s", rec.Body)
	}
}

// A value json cannot encode must produce a 500 that reveals nothing.
func TestWriteJSONHandlesUnencodableBody(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	rec := httptest.NewRecorder()
	h.srv.writeJSON(rec, http.StatusCreated, make(chan int))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "chan") {
		t.Errorf("leaked the encoder error: %s", rec.Body)
	}
}

func TestConcurrentUploadsGetDistinctPaths(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	const n = 16
	bodies := make([]*httptest.ResponseRecorder, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bodies[i] = h.upload(liveSecret,
				fmt.Sprintf("f%d.txt", i), "text/plain", "payload")
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	for i, rec := range bodies {
		if rec.Code != http.StatusCreated {
			t.Errorf("upload %d: status %d, want 201", i, rec.Code)
			continue
		}
		p := decodeUpload(t, rec).Path
		if seen[p] {
			t.Fatalf("duplicate path %q", p)
		}
		seen[p] = true
	}
	if len(seen) != n {
		t.Errorf("got %d distinct paths, want %d", len(seen), n)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()
	tokenPath := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(tokenPath,
		[]byte("live  "+liveSecret+"  -\n"), 0o600); err != nil {
		t.Fatalf("write tokens: %v", err)
	}
	a, err := auth.New(tokenPath, discardLogger())
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	st, err := store.New(filepath.Join(t.TempDir(), "d"), discardLogger())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer func() { _ = st.Close() }()
	log := discardLogger()

	if _, err := New(Options{Config: DefaultConfig(), Auth: a,
		Logger: log}); err == nil {
		t.Error("New without a store succeeded")
	}
	if _, err := New(Options{Config: DefaultConfig(), Store: st,
		Logger: log}); err == nil {
		t.Error("New without an authenticator succeeded")
	}
	cfg := DefaultConfig()
	cfg.MaxUploadBytes = 0
	if _, err := New(Options{Config: cfg, Store: st, Auth: a,
		Logger: log}); err == nil {
		t.Error("New with a zero upload limit succeeded")
	}
	cfg = DefaultConfig()
	cfg.MaxUploadBytes = 1 << 60
	if _, err := New(Options{Config: cfg, Store: st, Auth: a,
		Logger: log}); err == nil {
		t.Error("New with an absurd upload limit succeeded")
	}
}

// The default limit is quoted in the README, in the flag help and in the
// deployment manifests. Guard the number here so a change to the constant
// cannot leave the documentation quietly wrong.
func TestDefaultUploadLimit(t *testing.T) {
	t.Parallel()
	const want = 10 << 20 // 10 MiB
	if DefaultMaxUploadBytes != want {
		t.Errorf("DefaultMaxUploadBytes = %d, want %d (10 MiB)",
			DefaultMaxUploadBytes, want)
	}
	if got := DefaultConfig().MaxUploadBytes; got != DefaultMaxUploadBytes {
		t.Errorf("DefaultConfig().MaxUploadBytes = %d, want %d",
			got, DefaultMaxUploadBytes)
	}
	// The body cap leaves room for multipart framing above the file limit,
	// so it must always be the larger of the two.
	h := newHarness(t, "")
	if bodySlack <= 0 {
		t.Errorf("bodySlack = %d, want positive", bodySlack)
	}
	if h.srv.MaxUploadBytes() != DefaultMaxUploadBytes {
		t.Errorf("served limit = %d, want %d",
			h.srv.MaxUploadBytes(), DefaultMaxUploadBytes)
	}
}

// A default-sized upload must actually be accepted; a limit nobody can reach
// is as broken as one that is too small.
func TestDefaultLimitAcceptsAModerateFile(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "")
	// A fraction of the limit, to keep the test quick.
	payload := strings.Repeat("x", 1<<20)
	rec := h.upload(liveSecret, "a.bin", "", payload)
	if rec.Code != http.StatusCreated {
		t.Fatalf("1 MiB upload against a %d byte limit: status %d, want 201",
			DefaultMaxUploadBytes, rec.Code)
	}
	if got := decodeUpload(t, rec).Size; got != int64(len(payload)) {
		t.Errorf("size = %d, want %d", got, len(payload))
	}
}

func TestAccessors(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "", withLimit(4096))
	if got := h.srv.MaxUploadBytes(); got != 4096 {
		t.Errorf("MaxUploadBytes = %d, want 4096", got)
	}
	if h.srv.Addr() != DefaultConfig().Addr {
		t.Errorf("Addr = %q, want %q", h.srv.Addr(), DefaultConfig().Addr)
	}
}
