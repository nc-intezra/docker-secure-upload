// Package names validates usernames and builds the file names that are
// written into the outbox. Nothing a client sends is ever used as a path
// without passing through this package.
package names

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// usernamePattern matches the AD sAMAccountName-friendly subset we accept.
var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

// ErrBadUsername is returned for usernames that fail validation.
var ErrBadUsername = errors.New("username must start with a letter and use only a-z, 0-9, '.', '_' or '-' (max 32 characters)")

// NormalizeUsername lowercases and trims the name, then validates it.
func NormalizeUsername(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !usernamePattern.MatchString(s) {
		return "", ErrBadUsername
	}
	return s, nil
}

var batchIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-z][a-z0-9._-]{0,31}-[0-9a-f]{6}$`)

// NewBatchID returns an ID such as 20261030T141502Z-jsmith-a3f9c1.
// username must already be normalized.
func NewBatchID(now time.Time, username string) string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return fmt.Sprintf("%s-%s-%s", now.UTC().Format("20060102T150405Z"), username, hex.EncodeToString(b[:]))
}

// ValidBatchID reports whether s has the shape NewBatchID produces.
func ValidBatchID(s string) bool { return batchIDPattern.MatchString(s) }

const (
	maxSafeNameBytes = 120
	maxExtBytes      = 16
)

var reserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// SafeName turns a client-supplied file name into one that is safe on any
// filesystem: no directory part, ASCII letters, digits, '.', '_' and '-'
// only, no leading dot or dash, at most 120 bytes with the extension kept,
// and never a Windows reserved device name.
func SafeName(original string) string {
	// Drop any directory part, whichever separator the client used.
	s := strings.ReplaceAll(original, "\\", "/")
	s = path.Base(s)
	if s == "." || s == "/" {
		s = ""
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_'
		if !ok {
			r = '_'
		}
		if r == '_' {
			if lastUnderscore {
				continue
			}
			lastUnderscore = true
		} else {
			lastUnderscore = false
		}
		b.WriteRune(r)
	}
	s = strings.TrimLeft(b.String(), ".-")
	s = strings.TrimRight(s, ".") // Windows strips trailing dots
	if s == "" || s == "_" {
		s = "file"
	}

	if len(s) > maxSafeNameBytes {
		ext := path.Ext(s)
		if len(ext) > maxExtBytes || len(ext) <= 1 {
			ext = ""
		}
		s = s[:maxSafeNameBytes-len(ext)] + ext
	}

	stem := strings.ToLower(s)
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if reserved[stem] {
		s = "_" + s
	}
	return s
}

// OutboxName builds <batchid>_<seq>_<safe name>.
func OutboxName(batchID string, seq int, original string) string {
	return fmt.Sprintf("%s_%03d_%s", batchID, seq, SafeName(original))
}

// CleanOriginal makes a client file name fit to store and display: valid
// UTF-8, no control characters, at most 1024 bytes. It is still never used
// as a path.
func CleanOriginal(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("file name is not valid UTF-8")
	}
	if len(s) == 0 || len(s) > 1024 {
		return "", errors.New("file name must be 1 to 1024 bytes")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return "", errors.New("file name contains control characters")
		}
	}
	return s, nil
}
