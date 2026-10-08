// Package store writes uploaded objects to a local directory and hands back
// opaque, unguessable URLs for them.
//
// The security model in one sentence: every filesystem path this package
// touches is built from values it generated itself, and every path it accepts
// back is checked against the grammar of those values.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	// dirPerm is the mode an object directory ends up with: group writable
	// and setgid, so every file created inside inherits the directory's group
	// rather than the creating process's primary group. That is what lets a
	// pod that restarts under a different OpenShift random UID still read
	// what the previous UID wrote.
	//
	// fs.FileMode spells the setgid bit as ModeSetgid, not as the POSIX
	// 0o2000, so the two must not be confused.
	dirPerm = fs.ModeSetgid | fs.FileMode(0o770)
	// dirCreateMode is what Mkdir is asked for. os.Root.Mkdir rejects the
	// setgid bit outright, so pinPerm adds it immediately afterwards.
	dirCreateMode = fs.FileMode(0o770)
	// filePerm leaves files group-readable for the same reason. There is no
	// world access: nothing outside the pod's group has any business
	// reading the volume directly.
	filePerm = fs.FileMode(0o640)

	// tmpPrefix marks a partially written object. It can never collide with
	// a real name, because the prefix character is outside the base58
	// alphabet and real names are validated against that alphabet.
	tmpPrefix = ".tmp-"

	// mkdirAttempts bounds the retry loop for the astronomically unlikely
	// random directory name collision.
	mkdirAttempts = 8
)

var (
	// ErrTooLarge means the upload exceeded the caller's byte limit. The
	// partial file has been removed by the time this is returned.
	ErrTooLarge = errors.New("upload exceeds size limit")

	// ErrNotFound means there is no object at the requested path. It is
	// deliberately also the answer for a path that is merely malformed, so
	// that a caller can use neither the response nor its timing to discover
	// which paths are well-formed, nor whether a well-formed path exists.
	ErrNotFound = errors.New("object not found")
)

// Store is a directory of uploads. It is safe for concurrent use: every
// method touches only its own randomly named object.
type Store struct {
	dir string
	fs  *os.Root
	log *slog.Logger
}

// New prepares dir for use and returns a Store.
//
// It verifies that the directory is actually writable now rather than at first
// upload, so a missing or read-only volume mount fails at startup where an
// operator will see it, instead of surfacing later as a 500 to a client.
func New(dir string, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(dir, dirCreateMode); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open data dir: %w", err)
	}
	if err := probeWritable(root); err != nil {
		return nil, err
	}
	if err := pinPerm(filepath.Join(dir, ".writable"), filePerm); err != nil {
		return nil, err
	}
	if err := os.Remove(filepath.Join(dir, ".writable")); err != nil {
		return nil, fmt.Errorf("remove probe file: %w", err)
	}
	return &Store{dir: dir, fs: root, log: log}, nil
}

// Dir returns the directory backing the store.
func (s *Store) Dir() string { return s.dir }

// Close releases the store's directory handle.
func (s *Store) Close() error {
	if s.fs == nil {
		return nil
	}
	return s.fs.Close()
}

// Create streams r into a freshly named object and returns its metadata.
//
// At most limit bytes are retained; one byte beyond the limit is read so that
// an oversized upload is detectable without ever buffering more than the limit
// plus a byte. Exceeding the limit yields ErrTooLarge.
//
// The bytes land in a temp file and are renamed into place, so a concurrent
// reader can never observe a partial object, and an interrupted upload leaves
// nothing behind but a removed temp file.
func (s *Store) Create(r io.Reader, limit int64, meta Meta) (*Object, error) {
	// Truncate up front so the returned Meta matches what the sidecar
	// holds and what a later download reports in its headers.
	meta = Meta{
		Filename:    truncateRunes(meta.Filename, MaxFilenameLen),
		ContentType: truncateRunes(meta.ContentType, MaxFilenameLen),
	}
	// The name is minted before the directory so that the only failures
	// after the directory exists all have a temp file to clean up. It also
	// cannot collide: a name collision would need the freshly created,
	// otherwise empty directory to already hold that exact name.
	name, err := randomBase58(fileNameLen)
	if err != nil {
		return nil, err
	}
	dir, err := s.mkdirRandom()
	if err != nil {
		return nil, err
	}

	tmpRel := relPath(dir, tmpPrefix+name)
	size, sum, err := s.writeTmp(tmpRel, r, limit)
	if err != nil {
		s.discard(dir, tmpRel)
		return nil, err
	}

	// os.Root has no rename, and it is not missed here: both paths are built
	// from values this function just generated, so nothing attacker-supplied
	// participates in the call. The rename is within one directory, hence
	// always on one filesystem, hence always atomic.
	finalRel := relPath(dir, name)
	if err := os.Rename(filepath.Join(s.dir, tmpRel),
		filepath.Join(s.dir, finalRel)); err != nil {
		s.discard(dir, tmpRel)
		return nil, fmt.Errorf("finalize upload: %w", err)
	}
	// A sidecar failure is reported but does not fail the upload: the object
	// is already durably stored, and a download with no original filename is
	// a far better outcome than a lost file.
	if err := s.writeMeta(dir, name, meta); err != nil {
		s.log.Warn("stored object without its description",
			"path", Rel+"/"+dir+"/"+name, "err", err)
	}
	return &Object{
		Path:   Rel + "/" + dir + "/" + name,
		Name:   name,
		Size:   size,
		SHA256: hex.EncodeToString(sum),
		Meta:   meta,
	}, nil
}

// Open returns a reader for the object at the URL path p, which must match the
// shape produced by Create. The caller owns the returned file.
//
// Any failure, including a malformed path, yields ErrNotFound.
func (s *Store) Open(p string) (*os.File, error) {
	dir, name, ok := validatePath(p)
	if !ok {
		return nil, ErrNotFound
	}
	f, err := s.fs.Open(relPath(dir, name))
	if err != nil {
		return nil, ErrNotFound
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, ErrNotFound
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, ErrNotFound
	}
	return f, nil
}

// Stat returns metadata for the object at p without opening it for reading.
func (s *Store) Stat(p string) (fs.FileInfo, error) {
	dir, name, ok := validatePath(p)
	if !ok {
		return nil, ErrNotFound
	}
	info, err := s.fs.Stat(relPath(dir, name))
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrNotFound
	}
	return info, nil
}

// Delete removes the object at p along with its sidecar and, when left
// empty, its parent directory. Any valid bearer token may delete any known
// URL: knowledge of the unguessable path is the capability. A second delete
// reports ErrNotFound, exactly like a download of a missing object, so the
// response reveals nothing beyond what the caller already knew.
func (s *Store) Delete(p string) error {
	dir, name, ok := validatePath(p)
	if !ok {
		return ErrNotFound
	}
	rel := relPath(dir, name)
	info, err := s.fs.Stat(rel)
	if err != nil || !info.Mode().IsRegular() {
		return ErrNotFound
	}
	if err := s.fs.Remove(rel); err != nil {
		return ErrNotFound
	}
	_ = s.fs.Remove(relPath(dir, metaName(name)))
	// The directory holds at most this object and its sidecar, both now
	// gone, so a successful remove reclaims it; a failure means something
	// unexpected shares the directory and is safe to ignore.
	_ = s.fs.Remove(dir)
	return nil
}

// mkdirRandom creates and returns a new randomly named subdirectory.
func (s *Store) mkdirRandom() (string, error) {
	var name string
	var err error
	for range mkdirAttempts {
		if name, err = randomBase58(dirNameLen); err != nil {
			return "", err
		}
		err = s.fs.Mkdir(name, dirCreateMode)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("create object dir: %w", err)
		}
	}
	if err != nil {
		return "", fmt.Errorf("create object dir after %d attempts: %w",
			mkdirAttempts, err)
	}
	if err := pinPerm(filepath.Join(s.dir, name), dirPerm); err != nil {
		s.discard(name)
		return "", err
	}
	return name, nil
}

// writeTmp writes r to the store-relative path and returns the byte count and
// content digest. It does not remove the file on failure; the caller owns that.
func (s *Store) writeTmp(rel string, r io.Reader, limit int64) (
	int64, []byte, error,
) {
	f, err := s.fs.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return 0, nil, fmt.Errorf("create temp file: %w", err)
	}
	defer func() { _ = f.Close() }()

	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(r, limit+1))
	if err != nil {
		return 0, nil, fmt.Errorf("write upload: %w", err)
	}
	if n > limit {
		return 0, nil, ErrTooLarge
	}
	if err := pinPerm(filepath.Join(s.dir, rel), filePerm); err != nil {
		return 0, nil, err
	}
	// Flush to the device before the rename so that a pod killed between
	// the rename and the writeback cannot leave a named but empty object.
	if err := f.Sync(); err != nil {
		return 0, nil, fmt.Errorf("sync upload: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, nil, fmt.Errorf("close upload: %w", err)
	}
	return n, hash.Sum(nil), nil
}

// discard removes the debris of a failed upload. The temp file goes first,
// because a directory cannot be removed while it still holds entries, then the
// directory.
//
// Removing that temp file is the whole point. An oversized upload is only
// detected after its first limit+1 bytes have already been written, so
// without this the rejected request would still leave those bytes on disk,
// which is precisely the exhaustion the size limit exists to prevent.
func (s *Store) discard(dir string, tmp ...string) {
	for _, f := range tmp {
		_ = s.fs.Remove(f)
	}
	_ = s.fs.Remove(dir)
}

// relPath joins two generated names into a store-relative path.
func relPath(dir, name string) string {
	return dir + "/" + name
}

// probeWritable fails fast if the volume is mounted read-only.
func probeWritable(root *os.Root) error {
	f, err := root.OpenFile(".writable",
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("data dir %q is not writable: %w",
			root.Name(), err)
	}
	return f.Close()
}

// pinPerm sets an exact mode after creation. Both Mkdir and OpenFile mask the
// requested mode through the process umask, so on a host running umask 022 the
// group-write and setgid bits that OpenShift's fsGroup model depends on would
// silently not be set. Chmod is not umask-masked.
func pinPerm(path string, perm fs.FileMode) error {
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
