// Package limits caps what one browser session or one client address may
// have open at once: batches without a manifest, uploads still receiving,
// and bytes promised to unfinished uploads (audit finding H-3).
//
// Session caps stop one browser tab running away; address caps matter more,
// because a client can drop its cookie and start a new session at will.
package limits

import (
	"fmt"
	"sync"

	"github.com/nc-intezra/docker-secure-upload/internal/config"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

// Error is returned when a cap would be exceeded. Its message is safe to
// show to the user.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Checker serializes the check with the creation that follows it, so two
// concurrent requests cannot both squeeze under a cap.
type Checker struct {
	Session config.Limits
	IP      config.Limits
	Store   *store.Store
	mu      sync.Mutex
}

type usage struct {
	batches, uploads int
	reserved         int64
}

func (c *Checker) usage(match func(sessionHash, ip string) bool) usage {
	var u usage
	for _, b := range c.Store.OpenBatches() {
		if match(b.SessionHash, b.ClientIP) {
			u.batches++
		}
	}
	for _, up := range c.Store.UploadsIn(store.StateReceiving) {
		if match(up.SessionHash, up.ClientIP) {
			u.uploads++
			u.reserved += up.Size - up.Offset
		}
	}
	return u
}

// Batch runs create if one more open batch fits under both caps.
func (c *Checker) Batch(sessionHash, ip string, create func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(sessionHash, ip, 1, 0, 0); err != nil {
		return err
	}
	return create()
}

// Upload runs create if one more receiving upload of size bytes fits under
// both caps.
func (c *Checker) Upload(sessionHash, ip string, size int64, create func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(sessionHash, ip, 0, 1, size); err != nil {
		return err
	}
	return create()
}

func (c *Checker) check(sessionHash, ip string, batches, uploads int, size int64) error {
	type scope struct {
		name  string
		lim   config.Limits
		match func(string, string) bool
	}
	for _, s := range []scope{
		{"this browser session", c.Session, func(sh, _ string) bool { return sh == sessionHash }},
		{"your computer's address", c.IP, func(_, i string) bool { return i == ip }},
	} {
		u := c.usage(s.match)
		if batches > 0 && s.lim.OpenBatches > 0 && u.batches+batches > s.lim.OpenBatches {
			return &Error{fmt.Sprintf("too many batches still in progress from %s (limit %d); wait for some to finish", s.name, s.lim.OpenBatches)}
		}
		if uploads > 0 && s.lim.OpenUploads > 0 && u.uploads+uploads > s.lim.OpenUploads {
			return &Error{fmt.Sprintf("too many files still uploading from %s (limit %d); wait for some to finish", s.name, s.lim.OpenUploads)}
		}
		if size > 0 && s.lim.Reserved > 0 && u.reserved+size > s.lim.Reserved {
			return &Error{fmt.Sprintf("too much data still to arrive from %s (limit %s); wait for current uploads to finish", s.name, human(s.lim.Reserved))}
		}
	}
	return nil
}

func human(n int64) string {
	const gib = 1 << 30
	if n >= gib {
		return fmt.Sprintf("%.0f GiB", float64(n)/gib)
	}
	return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
}
