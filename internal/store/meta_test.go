package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetaRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	want := Meta{
		Filename:    "Quarterly Report v2 FINAL.pdf",
		ContentType: "application/pdf",
	}
	obj, err := s.Create(strings.NewReader("payload"), 1<<20, want)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.ReadMeta(obj.Path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if got != want {
		t.Errorf("meta = %+v, want %+v", got, want)
	}
}

func TestMetaIsPreservedNotUsedForPaths(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// A filename engineered to escape must round-trip as data and must not
	// influence where anything was written.
	want := Meta{Filename: "../../../../etc/shadow"}
	obj, err := s.Create(strings.NewReader("x"), 1<<20, want)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, ok := validatePath(obj.Path); !ok {
		t.Fatalf("stored path %q is not well formed", obj.Path)
	}
	got, err := s.ReadMeta(obj.Path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if got.Filename != want.Filename {
		t.Errorf("Filename = %q, want %q", got.Filename, want.Filename)
	}
}

func TestMetaIsOptional(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	obj, err := s.Create(strings.NewReader("x"), 1<<20, Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// A present but empty sidecar reads back empty, without error.
	got, err := s.ReadMeta(obj.Path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if got != (Meta{}) {
		t.Errorf("meta = %+v, want empty", got)
	}
}

// Losing the sidecar must cost the description, not the file.
func TestReadMetaToleratesMissingSidecar(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	obj, err := s.Create(strings.NewReader("x"), 1<<20,
		Meta{Filename: "keep.txt"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dir, name, _ := strings.Cut(
		strings.TrimPrefix(obj.Path, Rel+"/"), "/")
	if err := s.fs.Remove(relPath(dir, metaName(name))); err != nil {
		t.Fatalf("Remove meta: %v", err)
	}
	got, err := s.ReadMeta(obj.Path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if got != (Meta{}) {
		t.Errorf("meta = %+v, want empty", got)
	}
	// The object itself must still be there.
	if _, err := s.Open(obj.Path); err != nil {
		t.Errorf("Open after meta loss: %v", err)
	}
}

func TestReadMetaToleratesCorruptSidecar(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	obj, err := s.Create(strings.NewReader("x"), 1<<20, Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dir, name, _ := strings.Cut(
		strings.TrimPrefix(obj.Path, Rel+"/"), "/")
	rel := relPath(dir, metaName(name))
	if err := os.WriteFile(filepath.Join(s.dir, rel),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt meta: %v", err)
	}
	if got, err := s.ReadMeta(obj.Path); err != nil || got != (Meta{}) {
		t.Errorf("ReadMeta = %+v, %v; want empty, nil", got, err)
	}
}

// The sidecar must not itself be addressable: its name does not match the
// object grammar, so a request for it is a miss rather than a leak.
func TestSidecarIsNotServable(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	obj, err := s.Create(strings.NewReader("secret"), 1<<20,
		Meta{Filename: "notes.txt"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sidecar := obj.Path + metaSuffix
	if _, _, ok := validatePath(sidecar); ok {
		t.Errorf("validatePath(%q) accepted a sidecar path", sidecar)
	}
	if _, err := s.Open(sidecar); err == nil {
		t.Errorf("Open(%q) succeeded, want not found", sidecar)
	}
	// A malformed path is a miss, exactly as Open would report.
	if _, err := s.ReadMeta(sidecar); err == nil {
		t.Errorf("ReadMeta(%q) succeeded, want not found", sidecar)
	}
}

func TestTruncateRunes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"under limit", "abc", 5, "abc"},
		{"exactly limit", "abcde", 5, "abcde"},
		{"over limit", "abcdef", 5, "abcde"},
		{"multibyte under", "héllo", 10, "héllo"},
		{"multibyte over", "héllo", 3, "hél"},
		{"invalid utf8 repaired",
			"a\xffb", 10, "ab"},
		{"empty", "", 5, ""},
		{"zero limit", "abc", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := truncateRunes(tc.in, tc.n); got != tc.want {
				t.Errorf("truncateRunes(%q, %d) = %q, want %q",
					tc.in, tc.n, got, tc.want)
			}
		})
	}
}

func TestOverlongFilenameIsTruncated(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	long := strings.Repeat("é", MaxFilenameLen+50)
	obj, err := s.Create(strings.NewReader("x"), 1<<20,
		Meta{Filename: long})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.ReadMeta(obj.Path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if n := len([]rune(got.Filename)); n != MaxFilenameLen {
		t.Errorf("stored filename is %d runes, want %d",
			n, MaxFilenameLen)
	}
}
