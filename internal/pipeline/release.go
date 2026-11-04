package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

// The operator commands below are what an administrator uses on held files
// until the admin web view exists. Each needs a name and a reason, and each
// is recorded in the audit log.

// Withheld returns uploads in quarantine/, held or infected, oldest first.
func (p *Pipeline) Withheld() []store.Upload {
	return p.Store.UploadsIn(store.StateHeld, store.StateQuarantined)
}

func checkOperator(by, reason string) error {
	for name, v := range map[string]string{"name": by, "reason": reason} {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("a %s is required", name)
		}
		if len(v) > 500 || !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("the %s must be plain text of at most 500 bytes", name)
		}
	}
	return nil
}

// Release sends a held file to the outbox. Only files held for a scan
// error, an oversize file or an outbox clash can be released: an infected
// (quarantined) file never can. The file is hashed again first, and refused
// if it no longer matches what the user sent.
func (p *Pipeline) Release(id, by, reason string) (store.Upload, error) {
	if err := checkOperator(by, reason); err != nil {
		return store.Upload{}, err
	}
	check := func() (store.Upload, error) {
		u, err := p.Store.Upload(id)
		if err != nil {
			return u, err
		}
		if u.State == store.StateQuarantined {
			return u, errors.New("infected files cannot be released")
		}
		if u.State != store.StateHeld || !u.Placed {
			return u, fmt.Errorf("only held files can be released; this one is %s", u.State)
		}
		return u, nil
	}
	u, err := check()
	if err != nil {
		return u, err
	}
	// Hash without holding the placement lock: a 40 GB file takes minutes.
	sum, err := hashFile(filepath.Join(p.Paths.Quarantine, u.ID))
	if err != nil {
		return u, fmt.Errorf("read held file: %w", err)
	}
	if sum != u.SHA256 {
		p.auditEvent("admin", strings.TrimSpace(by), "upload.release_refused", u, map[string]string{
			"reason": "SHA-256 no longer matches", "expected": u.SHA256, "actual": sum,
		})
		return u, fmt.Errorf("the held file's SHA-256 is %s but %s was received; not released", sum, u.SHA256)
	}

	p.placeMu.Lock()
	if u, err = check(); err != nil {
		p.placeMu.Unlock()
		return u, err
	}

	// If the batch is still open its manifest will list this file; once it
	// has closed the file gets a manifest of its own.
	p.closeMu.Lock()
	b, err := p.Store.Batch(u.BatchID)
	batchOpen := err == nil && b.ClosedAt.IsZero()
	u, err = p.Store.UpdateUpload(id, func(x *store.Upload) error {
		if x.State != store.StateHeld {
			return errors.New("state changed")
		}
		x.HeldReason = x.ScanReason
		x.State = store.StateReleased
		x.ReleasedBy = strings.TrimSpace(by)
		x.ReleaseReason = strings.TrimSpace(reason)
		x.ReleasedAt = p.now()
		x.Placed = false
		x.SidecarDone = false
		x.ManifestDone = batchOpen
		return nil
	})
	p.closeMu.Unlock()
	p.placeMu.Unlock()
	if err != nil {
		return u, err
	}
	p.auditEvent("admin", u.ReleasedBy, "upload.released", u, map[string]string{
		"reason": u.ReleaseReason, "held_reason": u.HeldReason, "sha256": u.SHA256, "outbox_name": u.OutboxName,
	})
	p.Log.Info("held file released", "upload", u.ID, "by", u.ReleasedBy, "name", u.OutboxName)
	p.finish(u)
	return p.Store.Upload(id)
}

// Discard deletes a held or quarantined file now instead of waiting for the
// retention period.
func (p *Pipeline) Discard(id, by, reason string) (store.Upload, error) {
	if err := checkOperator(by, reason); err != nil {
		return store.Upload{}, err
	}
	p.placeMu.Lock()
	defer p.placeMu.Unlock()
	u, err := p.Store.Upload(id)
	if err != nil {
		return u, err
	}
	if (u.State != store.StateHeld && u.State != store.StateQuarantined) || !u.Placed {
		return u, fmt.Errorf("only held or quarantined files can be deleted; this one is %s", u.State)
	}
	if err := os.Remove(filepath.Join(p.Paths.Quarantine, u.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return u, err
	}
	prev := u.State
	u, err = p.Store.UpdateUpload(id, func(x *store.Upload) error {
		x.State = store.StateDeleted
		x.ScanReason = fmt.Sprintf("%s (%s); deleted by %s: %s", prev, x.ScanReason, strings.TrimSpace(by), strings.TrimSpace(reason))
		return nil
	})
	if err != nil {
		return u, err
	}
	p.auditEvent("admin", strings.TrimSpace(by), "upload.discarded", u, map[string]string{
		"reason": strings.TrimSpace(reason), "previous_state": string(prev),
	})
	return u, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
