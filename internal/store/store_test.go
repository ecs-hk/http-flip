package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRandomBase58Shape(t *testing.T) {
	t.Parallel()
	const alphabet = base58
	for i := range 200 {
		got, err := randomBase58(fileNameLen)
		if err != nil {
			t.Fatalf("randomBase58: %v", err)
		}
		if len(got) != fileNameLen {
			t.Fatalf("iteration %d: len = %d, want %d",
				i, len(got), fileNameLen)
		}
		if strings.ContainsFunc(got, func(r rune) bool {
			return !strings.ContainsRune(alphabet, r)
		}) {
			t.Fatalf("iteration %d: %q outside alphabet", i, got)
		}
	}
}

func TestRandomBase58CoversAlphabet(t *testing.T) {
	t.Parallel()
	// 60k draws is far more than enough to hit all 58 symbols while keeping
	// the chance of a flake negligible.
	seen := map[rune]bool{}
	for range 4000 {
		got, err := randomBase58(16)
		if err != nil {
			t.Fatalf("randomBase58: %v", err)
		}
		for _, r := range got {
			seen[r] = true
		}
	}
	for _, r := range base58 {
		if !seen[r] {
			t.Errorf("alphabet symbol %q never generated", r)
		}
	}
}

// The rejection threshold must split evenly into the alphabet, so every one
// of the 58 symbols is produced by the same number of source bytes. 256 is not
// a multiple of 58, which is precisely why the modulo bias needs rejecting
// rather than arithmetic.
func TestBase58LimitCoversAlphabetUniformly(t *testing.T) {
	t.Parallel()
	if n := len(base58); n != 58 {
		t.Errorf("len(base58) = %d, want 58", n)
	}
	if base58Limit > 256 {
		t.Errorf("base58Limit = %d, must not exceed 256", base58Limit)
	}
	if r := base58Limit % base58Count; r != 0 {
		t.Errorf("base58Limit %% %d = %d, want 0",
			base58Count, r)
	}
	if per := base58Limit / base58Count; per != 4 {
		t.Errorf("source bytes per symbol = %d, want 4", per)
	}
	// Everything at or above the threshold is discarded, so the rejection
	// rate is bounded by (256-base58Limit)/256.
	if rate := float64(256-base58Limit) / 256; rate > 0.1 {
		t.Errorf("rejection rate %.3f is implausibly high", rate)
	}
}

func TestValidatePath(t *testing.T) {
	t.Parallel()
	const (
		goodDir  = "XcFCyemkp1GeXYZq"
		goodName = "9mZqT4rKxW2vNbHdY7pLcAeFjGhQwErT"
	)
	// Guard the fixtures themselves, so a future typo here reports itself
	// rather than quietly invalidating every case derived from it.
	if !dirNamePattern.MatchString(goodDir) {
		t.Fatalf("fixture goodDir %q does not match", goodDir)
	}
	if !fileNamePattern.MatchString(goodName) {
		t.Fatalf("fixture goodName %q does not match", goodName)
	}
	tests := []struct {
		name string
		path string
		ok   bool
	}{
		{"valid", Rel + "/" + goodDir + "/" + goodName, true},
		{"missing prefix", "/" + goodDir + "/" + goodName, false},
		{"wrong prefix", "/files/" + goodDir + "/" + goodName, false},
		{"prefix only", Rel, false},
		{"prefix slash only", Rel + "/", false},
		{"dir only", Rel + "/" + goodDir, false},
		{"empty", "", false},
		{"trailing slash", Rel + "/" + goodDir + "/" + goodName + "/", false},
		{"extra segment",
			Rel + "/" + goodDir + "/" + goodName + "/extra", false},
		{"dot dot escape", Rel + "/../" + goodDir + "/" + goodName, false},
		{"dot dot escape after valid dir",
			Rel + "/" + goodDir + "/../../etc/passwd", false},
		{"slash in name",
			Rel + "/" + goodDir + "/" + goodName[:16] + "/etc/passwd", false},
		{"trailing newline on dir",
			Rel + "/" + goodDir + "\n/" + goodName, false},
		{"trailing newline on name",
			Rel + "/" + goodDir + "/" + goodName + "\n", false},
		{"leading newline on dir",
			Rel + "/\n" + goodDir + "/" + goodName, false},
		{"dir too short", Rel + "/" + goodDir[:15] + "/" + goodName, false},
		{"dir too long", Rel + "/" + goodDir + "Z" + "/" + goodName, false},
		{"name too short",
			Rel + "/" + goodDir + "/" + goodName[:31], false},
		{"name too long",
			Rel + "/" + goodDir + "/" + goodName + "Z", false},
		{"dir is dots", Rel + "/" + strings.Repeat(".", 16) + "/" + goodName,
			false},
		{"name contains dot",
			Rel + "/" + goodDir + "/" + goodName[:31] + ".", false},
		{"name contains nul",
			Rel + "/" + goodDir + "/" + goodName[:31] + "\x00", false},
		{"dir contains nul",
			Rel + "/" + goodDir[:15] + "\x00/" + goodName, false},
		{"dir contains excluded 0",
			Rel + "/" + goodDir[:15] + "0/" + goodName, false},
		{"dir contains excluded I",
			Rel + "/" + goodDir[:15] + "I/" + goodName, false},
		{"dir contains excluded O",
			Rel + "/" + goodDir[:15] + "O/" + goodName, false},
		{"name contains excluded l",
			Rel + "/" + goodDir + "/" + goodName[:31] + "l", false},
		{"encoded traversal",
			Rel + "/" + goodDir + "/%2e%2e%2f%2e%2e%2fetc%2fpasswd", false},
		{"backslash", Rel + "/" + goodDir + "/" + goodName + `\`, false},
		{"absolute after prefix",
			Rel + "/" + goodDir + "//etc/passwd", false},
		{"space", Rel + "/" + goodDir + "/" + goodName + " ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, name, ok := validatePath(tc.path)
			if ok != tc.ok {
				t.Fatalf("validatePath(%q) ok = %v, want %v",
					tc.path, ok, tc.ok)
			}
			if !ok {
				return
			}
			if dir != goodDir || name != goodName {
				t.Errorf("components = %q/%q, want %q/%q",
					dir, name, goodDir, goodName)
			}
		})
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := New(dir, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func TestCreateRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	payload := []byte("the quick brown fox jumps over the lazy dog")

	obj, err := s.Create(bytes.NewReader(payload), int64(len(payload)), Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if obj.Size != int64(len(payload)) {
		t.Errorf("Size = %d, want %d", obj.Size, len(payload))
	}
	want := sha256.Sum256(payload)
	if obj.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("SHA256 = %s, want %s", obj.SHA256,
			hex.EncodeToString(want[:]))
	}

	f, err := s.Open(obj.Path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("content = %q, want %q", got, payload)
	}
}

func TestCreatePathShape(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// The caller-supplied name must not influence the stored path at all.
	obj, err := s.Create(
		strings.NewReader("x"), 1<<20,
		Meta{Filename: "../../etc/passwd"},
	)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dir, name, ok := validatePath(obj.Path)
	if !ok {
		t.Fatalf("returned path %q is not self-consistent", obj.Path)
	}
	if len(dir) != dirNameLen || len(name) != fileNameLen {
		t.Errorf("segment lengths = %d/%d, want %d/%d",
			len(dir), len(name), dirNameLen, fileNameLen)
	}
}

func TestCreateEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	obj, err := s.Create(bytes.NewReader(nil), 1024, Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if obj.Size != 0 {
		t.Errorf("Size = %d, want 0", obj.Size)
	}
	if obj.SHA256 !=
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("SHA256 of empty input = %s", obj.SHA256)
	}
	f, err := s.Open(obj.Path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("content = %q, want empty", got)
	}
}

func TestCreateTooLargeLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, err := s.Create(strings.NewReader("0123456789"), 5, Meta{})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Create err = %v, want ErrTooLarge", err)
	}
	entries, err := os.ReadDir(s.Dir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("store not empty after rejected upload: %v", names)
	}
}

func TestCreateAtExactLimit(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	payload := strings.Repeat("x", 512)
	obj, err := s.Create(strings.NewReader(payload), int64(len(payload)), Meta{})
	if err != nil {
		t.Fatalf("Create at exact limit: %v", err)
	}
	if obj.Size != int64(len(payload)) {
		t.Errorf("Size = %d, want %d", obj.Size, len(payload))
	}
}

func TestOpenMissing(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	dir, err := randomBase58(dirNameLen)
	if err != nil {
		t.Fatalf("randomBase58: %v", err)
	}
	name, err := randomBase58(fileNameLen)
	if err != nil {
		t.Fatalf("randomBase58: %v", err)
	}
	if _, err := s.Open(Rel + "/" + dir + "/" + name); !errors.Is(
		err, ErrNotFound,
	) {
		t.Fatalf("Open err = %v, want ErrNotFound", err)
	}
}

func TestOpenMalformed(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	for _, p := range []string{
		"",
		Rel,
		Rel + "/../../etc/passwd",
		Rel + "/" + strings.Repeat("a", 16) + "/" +
			strings.Repeat("a", 32) + "/../..",
		"/etc/passwd",
	} {
		if _, err := s.Open(p); !errors.Is(err, ErrNotFound) {
			t.Errorf("Open(%q) err = %v, want ErrNotFound", p, err)
		}
	}
}

func TestOpenDirectoryIsNotAnObject(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// A directory whose name happens to match the object grammar must still
	// not be servable.
	dir, err := randomBase58(dirNameLen)
	if err != nil {
		t.Fatalf("randomBase58: %v", err)
	}
	if err := s.fs.Mkdir(dir, dirCreateMode); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	name, err := randomBase58(fileNameLen)
	if err != nil {
		t.Fatalf("randomBase58: %v", err)
	}
	if _, err := s.Open(Rel + "/" + dir + "/" + name); !errors.Is(
		err, ErrNotFound,
	) {
		t.Fatalf("Open err = %v, want ErrNotFound", err)
	}
}

// The store pins exact modes rather than relying on Mkdir/OpenFile and the
// process umask, which is what the OpenShift random-UID story depends on.
func TestPinnedPermissions(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	obj, err := s.Create(strings.NewReader("x"), 1024, Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rel := strings.TrimPrefix(obj.Path, Rel+"/")
	info, err := s.fs.Stat(rel)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("object perm = %o, want 640", got)
	}
	dinfo, err := s.fs.Stat(strings.SplitN(rel, "/", 2)[0])
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if got := dinfo.Mode().Perm(); got != 0o770 {
		t.Errorf("dir perm = %o, want 770", got)
	}
	if dinfo.Mode()&fs.ModeSetgid == 0 {
		t.Error("object dir lost its setgid bit")
	}
}

func TestConcurrentCreatesAreDistinct(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const n = 24
	paths := make(chan string, n)
	errs := make(chan error, n)
	for range n {
		go func() {
			obj, err := s.Create(strings.NewReader("payload"), 1024, Meta{})
			if err != nil {
				errs <- err
				return
			}
			paths <- obj.Path
		}()
	}
	seen := make(map[string]bool, n)
	for range n {
		select {
		case err := <-errs:
			t.Fatalf("concurrent Create: %v", err)
		case p := <-paths:
			if seen[p] {
				t.Fatalf("duplicate path %q", p)
			}
			seen[p] = true
		}
	}
}

func TestDeleteRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	obj, err := s.Create(strings.NewReader("payload"), 1024,
		Meta{Filename: "a.txt"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(obj.Path); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Open(obj.Path); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open after Delete = %v, want ErrNotFound", err)
	}
	if err := s.Delete(obj.Path); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
	entries, err := os.ReadDir(s.Dir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("store has %d entries after Delete", len(entries))
	}
}

func TestDeleteMalformedIsNotFound(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	for _, p := range []string{"", Rel, Rel + "/../../etc/passwd"} {
		if err := s.Delete(p); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(%q) = %v, want ErrNotFound", p, err)
		}
	}
}

// A removal that fails for a reason other than absence is a
// storage failure, not a miss: the object is still there, and a
// not-found answer would claim a deletion that did not happen.
func TestDeleteStorageFailureIsNotNotFound(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	s := newStore(t)
	obj, err := s.Create(strings.NewReader("payload"), 1024, Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dir, _, ok := validatePath(obj.Path)
	if !ok {
		t.Fatalf("path %q is not well formed", obj.Path)
	}
	// Removing an entry needs write permission on the directory
	// holding it; take that away to make the remove fail.
	objDir := filepath.Join(s.dir, dir)
	if err := os.Chmod(objDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(objDir, dirPerm) }()

	err = s.Delete(obj.Path)
	if err == nil {
		t.Fatal("Delete succeeded against a read-only directory, want error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete = %v, want a storage failure, not not-found", err)
	}
	if !errors.Is(err, ErrRemove) {
		t.Fatalf("Delete = %v, want it to wrap ErrRemove", err)
	}
	// The object must have survived the failed delete.
	if _, err := s.Open(obj.Path); err != nil {
		t.Errorf("Open after a failed delete = %v, want the object intact", err)
	}
}

func TestCreateReturnsTruncatedMeta(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	long := strings.Repeat("x", MaxFilenameLen+50)
	obj, err := s.Create(strings.NewReader("x"), 1<<20,
		Meta{Filename: long})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n := len([]rune(obj.Meta.Filename)); n != MaxFilenameLen {
		t.Errorf("returned filename is %d runes, want %d",
			n, MaxFilenameLen)
	}
}

func TestNewRejectsUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "data")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if _, err := New(dir, discardLogger()); err == nil {
		t.Error("New succeeded on a read-only directory, want error")
	}
}

// An upload interrupted by a killed pod leaves a temp file whose name was
// never handed to a client. Startup must reclaim it and the empty directory
// around it, and must not disturb a completed object.
func TestNewSweepsInterruptedUploads(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := New(dir, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obj, err := s.Create(strings.NewReader("payload"), 1024,
		Meta{Filename: "keep.txt"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	objDir, _, ok := validatePath(obj.Path)
	if !ok {
		t.Fatalf("stored path %q is not well formed", obj.Path)
	}

	// Debris beside a live object.
	stray := filepath.Join(dir, objDir, tmpPrefix+"abandoned")
	if err := os.WriteFile(stray, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write stray: %v", err)
	}
	// A directory holding nothing but debris.
	debrisDir, err := randomBase58(dirNameLen)
	if err != nil {
		t.Fatalf("randomBase58: %v", err)
	}
	if err := s.fs.Mkdir(debrisDir, dirCreateMode); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	debris := filepath.Join(dir, debrisDir, tmpPrefix+"abandoned")
	if err := os.WriteFile(debris, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write debris: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := New(dir, discardLogger())
	if err != nil {
		t.Fatalf("New after debris: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	for _, gone := range []string{stray, filepath.Dir(debris)} {
		if _, err := os.Stat(gone); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s survived the sweep (err = %v)", gone, err)
		}
	}
	// The completed object, its sidecar and its directory are untouched.
	f, err := s2.Open(obj.Path)
	if err != nil {
		t.Fatalf("Open after sweep: %v", err)
	}
	_ = f.Close()
	meta, err := s2.ReadMeta(obj.Path)
	if err != nil {
		t.Fatalf("ReadMeta after sweep: %v", err)
	}
	if meta.Filename != "keep.txt" {
		t.Errorf("filename after sweep = %q, want keep.txt", meta.Filename)
	}
}
