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
	"unicode"
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

// maxSafeNameBytes keeps every outbox name, with the optional 61-byte
// batch prefix and the 7-byte ".sha256" suffix, under the 255-byte limit of
// common filesystems.
const (
	maxSafeNameBytes = 180
	maxExtBytes      = 16
)

var reserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// unsafeRune reports characters that cannot appear in a file name on Linux
// or Windows, or that would make the name misleading or hard to handle:
// control characters, line separators and the Windows-reserved punctuation.
// It also rejects every Unicode format character (category Cf): the
// right-to-left override, bidirectional isolates, zero-width characters and
// the byte-order mark, which can make "report\u202Efdp.exe" display as
// "reportexe.pdf" (audit finding M-2).
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0, r == '\u2028', r == '\u2029':
		return true
	case unicode.Is(unicode.Cf, r):
		return true
	}
	return strings.ContainsRune(`<>:"/\|?*`, r)
}

// reservedSuffixes are endings the service uses for the files it writes
// itself. Uploaded names that end this way get a trailing "_" so they can
// never be mistaken for a sidecar or manifest (audit finding M-3).
var reservedSuffixes = []string{".sha256", ".manifest.json"}

// SafeName keeps the user's file name as written wherever it is safe, so the
// file arrives with the name its sender expects. It only:
//   - drops any directory part, whichever separator the client used;
//   - replaces characters that are illegal on Linux or Windows (control
//     characters and < > : " / \ | ? *) with '_';
//   - removes leading dots (hidden files) and leading or trailing spaces, and
//     trailing dots (Windows strips them);
//   - prefixes Windows device names such as CON or NUL with '_';
//   - replaces invisible and direction-changing Unicode characters with '_';
//   - shortens names over 180 bytes, keeping the extension;
//   - appends '_' to names ending in .sha256 or .manifest.json, which are
//     reserved for the files the service writes itself.
//
// Spaces, letters in any script, and other punctuation are kept.
func SafeName(original string) string {
	s := strings.ReplaceAll(original, "\\", "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unsafeRune(r) {
			r = '_'
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	s = strings.TrimLeft(s, ".")
	s = strings.TrimSpace(strings.TrimRight(s, ". "))
	if strings.Trim(s, "_") == "" {
		s = "file"
	}

	if len(s) > maxSafeNameBytes {
		ext := path.Ext(s)
		if len(ext) > maxExtBytes || len(ext) <= 1 {
			ext = ""
		}
		stem := s[:len(s)-len(ext)]
		cut := maxSafeNameBytes - len(ext)
		for cut > 0 && !utf8.RuneStart(stem[cut]) {
			cut-- // never split a multi-byte character
		}
		s = strings.TrimRight(stem[:cut], ". ") + ext
	}

	stem := strings.ToLower(s)
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if reserved[strings.TrimSpace(stem)] {
		s = "_" + s
	}
	lower := strings.ToLower(s)
	for _, suf := range reservedSuffixes {
		if strings.HasSuffix(lower, suf) {
			s += "_"
			break
		}
	}
	return s
}

// OutboxName returns the name a file gets in the outbox: its safe name, or,
// when the sender opted in, <batchid>_<seq>_<safe name>.
func OutboxName(batchID string, seq int, original string, prefix bool) string {
	if !prefix {
		return SafeName(original)
	}
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
