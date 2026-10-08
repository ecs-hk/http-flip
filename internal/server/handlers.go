package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/mropc/http-flip/internal/auth"
	"github.com/mropc/http-flip/internal/store"
)

// bodySlack is how far above MaxUploadBytes the request body may run before
// the connection is cut.
//
// Multipart framing wraps the payload in boundaries and part headers, so a
// client uploading exactly MaxUploadBytes would otherwise be rejected for the
// bytes around it. The slack covers that framing and no more; the precise
// per-file limit is enforced by the store as it streams, so a body far over
// the limit is still refused.
const bodySlack = 64 << 10

// errMultipleFiles reports a request carrying more than one file part.
var errMultipleFiles = errors.New("more than one file part")

// readErr marks a failure to make sense of the request body, which is a
// client fault by definition. It exists so that refuseUpload can tell a bad
// request from a good one the server failed to store, by type rather than by
// matching on message text.
type readErr struct{ err error }

func (e readErr) Error() string { return e.err.Error() }

func (e readErr) Unwrap() error { return e.err }

// uploadResponse is the JSON body of a successful upload.
type uploadResponse struct {
	Path        string `json:"path"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	UploadedBy  string `json:"uploaded_by"`
}

// handleUpload accepts one multipart file part, stores it, and returns the URL
// it can be downloaded from.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)

	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(media, "multipart/") {
		s.log.Warn("refused upload with unusable content type",
			"token", id.Token, "content_type",
			r.Header.Get("Content-Type"))
		s.writeJSON(w, http.StatusUnsupportedMediaType,
			errorBody{Error: "expected a multipart/form-data body"})
		return
	}

	// Bound the body before reading any of it, so an oversized upload is
	// refused rather than consumed.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes+bodySlack)

	mr, err := r.MultipartReader()
	if err != nil {
		s.refuseUpload(w, r, id, readErr{err})
		return
	}

	var (
		obj  *store.Object
		meta store.Meta
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.refuseUpload(w, r, id, readErr{err})
			return
		}
		// A part without a filename is an ordinary form field. This service
		// stores only files, so there is nothing to do with one.
		if part.FileName() == "" {
			_ = part.Close()
			continue
		}
		if obj != nil {
			// Refused rather than ignored, because silently discarding an
			// upload would leave the client believing both were saved. The
			// first part is already stored at this point, so remove it:
			// an orphan would otherwise consume quota with no URL ever
			// returned for it.
			_ = part.Close()
			if err := s.store.Delete(obj.Path); err != nil {
				s.log.Warn("could not clean up first part of "+
					"rejected multi-part upload",
					"token", id.Token, "path", obj.Path, "err", err)
			}
			s.refuseUpload(w, r, id, errMultipleFiles)
			return
		}
		meta = store.Meta{
			Filename:    part.FileName(),
			ContentType: part.Header.Get("Content-Type"),
		}
		obj, err = s.store.Create(part, s.cfg.MaxUploadBytes, meta)
		_ = part.Close()
		if err != nil {
			s.refuseUpload(w, r, id, err)
			return
		}
	}

	if obj == nil {
		s.writeJSON(w, http.StatusBadRequest,
			errorBody{Error: "the request contained no file part"})
		return
	}

	s.log.Info("stored upload",
		"token", id.Token, "path", obj.Path, "size", obj.Size,
		"filename", obj.Meta.Filename, "sha256", obj.SHA256, "remote",
		remoteOf(r), "client", clientOf(r))

	s.writeJSON(w, http.StatusCreated, uploadResponse{
		Path:        obj.Path,
		Filename:    obj.Meta.Filename,
		ContentType: obj.Meta.ContentType,
		Size:        obj.Size,
		SHA256:      obj.SHA256,
		UploadedBy:  id.Token,
	})
}

// refuseUpload maps a failure while reading or storing an upload onto a
// status. The distinction that matters is whose fault it was: a malformed or
// oversized body is the client's, and anything else is ours, because telling
// a well-behaved client that its request was malformed would send it looking
// for a problem it does not have.
func (s *Server) refuseUpload(
	w http.ResponseWriter, r *http.Request, id auth.Identity, err error,
) {
	var (
		oversized *http.MaxBytesError
		malformed readErr
	)
	switch {
	case errors.Is(err, errMultipleFiles):
		s.log.Warn("refused upload with multiple file parts",
			"token", id.Token, "remote", remoteOf(r))
		s.writeJSON(w, http.StatusBadRequest, errorBody{
			Error: "exactly one file part is permitted",
		})
	case errors.Is(err, store.ErrTooLarge), errors.As(err, &oversized):
		s.log.Warn("refused oversized upload",
			"token", id.Token, "limit", s.cfg.MaxUploadBytes,
			"remote", remoteOf(r))
		s.writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{
			Error: "file exceeds the maximum permitted size",
		})
	case errors.As(err, &malformed):
		s.log.Warn("refused malformed upload",
			"token", id.Token, "err", err, "remote", remoteOf(r))
		s.writeJSON(w, http.StatusBadRequest, errorBody{
			Error: "the request body could not be read as multipart data",
		})
	default:
		s.log.Error("failed to store upload",
			"token", id.Token, "err", err, "remote", remoteOf(r))
		s.writeJSON(w, http.StatusInternalServerError,
			errorBody{Error: "internal error"})
	}
}

// handleDownload streams a stored object.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.Open(r.URL.Path)
	if err != nil {
		s.notFound(w)
		return
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		s.notFound(w)
		return
	}
	meta, err := s.store.ReadMeta(r.URL.Path)
	if err != nil {
		s.notFound(w)
		return
	}

	// Fall back to the object's own name so that a download whose sidecar
	// was lost still saves as something unique rather than "download".
	name := meta.Filename
	if name == "" {
		name = path.Base(r.URL.Path)
	}

	h := w.Header()
	// Set explicitly rather than left to ServeContent's sniffing: the bytes
	// are arbitrary content from an authenticated but untrusted client, and
	// the whole point is that the browser must not be told what they are.
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", contentDisposition(name))
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	// The URL is the credential, so nothing about this response should be
	// retained in a shared cache.
	h.Set("Cache-Control", "no-store")

	// An empty name keeps ServeContent from inferring a type from an
	// extension; the header above is what it will report.
	http.ServeContent(w, r, "", info.ModTime(), f)
}

// handleDelete removes a stored object. It requires a valid bearer token,
// like uploads, but any valid token may delete any known URL: knowledge of
// the unguessable path is the capability, and the service keeps no
// per-object owner to check against. A reader holding an open download keeps
// its bytes; the name simply stops resolving.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	if err := s.store.Delete(r.URL.Path); err != nil {
		s.notFound(w)
		return
	}
	s.log.Info("deleted object",
		"token", id.Token, "path", r.URL.Path,
		"remote", remoteOf(r), "client", clientOf(r))
	w.WriteHeader(http.StatusNoContent)
}

// handleProbe answers liveness and readiness checks.
func (s *Server) handleProbe(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// handleNotFound answers any path this service does not serve. Because the
// catch-all is method-agnostic, it must restore the 405 distinction ServeMux
// would otherwise provide: a known path with the wrong method answers 405
// with Allow, everything else answers JSON 404.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/upload" {
		switch r.Method {
		case http.MethodPost, http.MethodPut:
		default:
			s.methodNotAllowed(w, "POST, PUT")
			return
		}
	}
	for _, probe := range []string{"/healthz", "/livez", "/readyz"} {
		if r.URL.Path == probe {
			switch r.Method {
			case http.MethodGet, http.MethodHead:
			default:
				s.methodNotAllowed(w, "GET")
				return
			}
		}
	}
	if store.IsObjectPath(r.URL.Path) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodDelete:
		default:
			s.methodNotAllowed(w, "GET, HEAD, DELETE")
			return
		}
	}
	s.notFound(w)
}

// methodNotAllowed answers a known path with the wrong method.
func (s *Server) methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	s.writeJSON(w, http.StatusMethodNotAllowed,
		errorBody{Error: "method not allowed"})
}

// notFound answers a missing object. A malformed path is answered the same
// way, so the response reveals nothing about which paths are well-formed or
// which of those exist.
func (s *Server) notFound(w http.ResponseWriter) {
	s.writeJSON(w, http.StatusNotFound, errorBody{Error: "not found"})
}

// attrChars are the characters RFC 6266 permits unescaped in a filename*.
const attrChars = "!#$&+-.^_`|~"

func isAttrByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte(attrChars, b) >= 0
}

// contentDisposition builds an attachment header from a client-supplied name.
//
// The name is attacker-controlled and is being placed in a response header, so
// CR and LF are removed outright: leaving them in would let an uploader inject
// arbitrary additional headers into somebody else's download response. Two
// forms are emitted so that modern browsers recover the real name and older
// ones still get something safe.
func contentDisposition(name string) string {
	ascii := strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			// Control characters, CR and LF included.
			return -1
		case r > 0x7e:
			return '_'
		case r == '"' || r == '\\':
			return '_'
		}
		return r
	}, name)
	ascii = strings.TrimSpace(ascii)
	if ascii == "" || ascii == "." || ascii == ".." {
		ascii = "download"
	}

	var encoded strings.Builder
	encoded.Grow(len(name))
	for _, b := range []byte(name) {
		if isAttrByte(b) {
			encoded.WriteByte(b)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteString(strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	if encoded.Len() == 0 {
		return `attachment; filename="` + ascii + `"`
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` +
		encoded.String()
}

// marshal is a seam for tests that need a failing encoder.
var marshal = func(v any) ([]byte, error) { return json.Marshal(v) }
