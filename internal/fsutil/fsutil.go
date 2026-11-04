// Package fsutil holds the small filesystem helpers the handoff depends on:
// atomic writes, directory fsync, same-device checks and free-space queries.
package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// FileMode is used for the service's private files: staging, quarantine,
// state and audit. clamd reads staging files through the service's group
// (compose gives it group 65532), so nothing needs to be world-readable.
const FileMode = 0o640

// PublicFileMode is used for what goes into the outbox, which the diode
// reads as a different user.
const PublicFileMode = 0o644

// DirMode is used for every directory the service creates.
const DirMode = 0o750

// SyncDir fsyncs a directory so that a rename into it survives a crash.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// WriteAtomic writes data to a temporary file in tmpDir, fsyncs it, and
// renames it to dest. tmpDir and dest must be on the same filesystem. The
// destination either does not exist or holds the complete data; it is never
// seen half-written.
func WriteAtomic(tmpDir, dest string, data []byte) error {
	return WriteAtomicMode(tmpDir, dest, data, FileMode)
}

// WriteAtomicMode is WriteAtomic with an explicit file mode.
func WriteAtomicMode(tmpDir, dest string, data []byte, mode os.FileMode) error {
	tmp, err := TempPath(tmpDir)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	// The umask may have removed bits the caller asked for.
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	ok = true
	return SyncDir(filepath.Dir(dest))
}

// MoveNoReplace renames src to dest, failing if dest already exists, then
// fsyncs the destination directory. Both must be on the same filesystem.
func MoveNoReplace(src, dest string) error {
	// os.Link fails with EEXIST if dest exists, which gives us an atomic
	// no-clobber rename on Linux without platform-specific syscalls.
	if err := os.Link(src, dest); err != nil {
		if errors.Is(err, os.ErrExist) {
			return err
		}
		// Some filesystems refuse hard links. Fall back to a checked
		// rename; names are unique per upload, so the window is harmless.
		if _, statErr := os.Lstat(dest); statErr == nil {
			return &os.LinkError{Op: "rename", Old: src, New: dest, Err: os.ErrExist}
		}
		if err := os.Rename(src, dest); err != nil {
			return err
		}
	} else if err := os.Remove(src); err != nil {
		return err
	}
	if err := SyncDir(filepath.Dir(dest)); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(src))
}

// TempPath returns an unused random path inside dir.
func TempPath(dir string) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return filepath.Join(dir, "tmp-"+hex.EncodeToString(b[:])), nil
}

// DeviceID returns the device number of the filesystem holding path.
func DeviceID(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("device id not available on this platform")
	}
	return uint64(st.Dev), nil //nolint:unconvert // Dev is int32 on some platforms
}

// SameDevice returns an error unless every path is on the same filesystem.
func SameDevice(paths ...string) error {
	var first uint64
	for i, p := range paths {
		dev, err := DeviceID(p)
		if err != nil {
			return err
		}
		if i == 0 {
			first = dev
		} else if dev != first {
			return fmt.Errorf("%s and %s are on different filesystems; atomic renames between them are impossible", paths[0], p)
		}
	}
	return nil
}

// FreeBytes returns the bytes available to an unprivileged user on the
// filesystem holding path.
func FreeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil //nolint:unconvert
}

// IsWithin reports whether child is parent or lies inside it. Both paths
// are cleaned and resolved through symlinks where they exist.
func IsWithin(parent, child string) bool {
	p := resolve(parent)
	c := resolve(child)
	if p == c {
		return true
	}
	rel, err := filepath.Rel(p, c)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func resolve(p string) string {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
