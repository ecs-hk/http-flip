package store

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	// metaSuffix marks the sidecar holding an object's caller-supplied
	// description. A sidecar is used rather than an extended attribute so
	// that this stays portable and dependency-free, and rather than folding
	// the name into the object path so that the name can never influence
	// where bytes land.
	metaSuffix = ".meta"

	// MaxFilenameLen bounds a stored original filename, so that a client
	// cannot write an arbitrarily large sidecar.
	MaxFilenameLen = 255

	// maxMetaLen bounds what ReadMeta will read. It must allow the longest
	// permitted field at its worst-case encoded width, plus room for the
	// JSON scaffolding: a filename of MaxFilenameLen runes can occupy 4
	// bytes each, and both fields are present at once. Sizing this from
	// character count instead silently truncates every sidecar holding a
	// non-ASCII name.
	maxMetaLen = 4*2*MaxFilenameLen + 256
)

// Meta is the caller-supplied description of an upload.
//
// It is advisory. An object must remain retrievable if its sidecar is missing
// or unreadable, because the bytes are what this service exists to keep.
type Meta struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
}

// Object describes a stored upload. Path is a URL path that can be handed
// straight back to a client for download.
type Object struct {
	Path   string `json:"path"`
	Name   string `json:"-"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Meta   Meta   `json:"meta"`
}

// writeMeta records the description alongside a freshly renamed object.
//
// This runs after the rename, so a sidecar failure leaves the object fully
// retrievable under its random name. Losing the description is a much smaller
// outcome than losing the file.
func (s *Store) writeMeta(dir, name string, meta Meta) error {
	meta = Meta{
		Filename:    truncateRunes(meta.Filename, MaxFilenameLen),
		ContentType: truncateRunes(meta.ContentType, MaxFilenameLen),
	}
	blob, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encode meta: %w", err)
	}
	rel := relPath(dir, metaName(name))
	f, err := s.fs.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("open meta: %w", err)
	}
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		return fmt.Errorf("write meta: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close meta: %w", err)
	}
	return pinPerm(filepath.Join(s.dir, rel), filePerm)
}

// ReadMeta returns the description recorded for the object at p.
//
// An absent or damaged sidecar yields an empty Meta and a nil error. Refusing
// to serve an object whose description was lost would turn a cosmetic loss
// into an outage.
func (s *Store) ReadMeta(p string) (Meta, error) {
	dir, name, ok := validatePath(p)
	if !ok {
		return Meta{}, ErrNotFound
	}
	f, err := s.fs.Open(relPath(dir, metaName(name)))
	if err != nil {
		return Meta{}, nil
	}
	defer func() { _ = f.Close() }()
	blob, err := io.ReadAll(io.LimitReader(f, maxMetaLen))
	if err != nil {
		return Meta{}, nil
	}
	var meta Meta
	if err := json.Unmarshal(blob, &meta); err != nil {
		return Meta{}, nil
	}
	return meta, nil
}

// metaName is the sidecar name for an object name.
func metaName(name string) string {
	return name + metaSuffix
}

// truncateRunes shortens s to at most n characters, counting characters rather
// than bytes so the result cannot be split mid-rune. Invalid input is
// normalised first, because it came from an arbitrary client.
func truncateRunes(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
