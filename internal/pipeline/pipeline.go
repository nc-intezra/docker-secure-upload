package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/audit"
	"github.com/nc-intezra/docker-secure-upload/internal/clamd"
	"github.com/nc-intezra/docker-secure-upload/internal/fsutil"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

// Scanner is the part of the clamd client the pipeline uses.
type Scanner interface {
	Ping(ctx context.Context) error
	Version(ctx context.Context) (clamd.Version, error)
	Scan(ctx context.Context, path string) (clamd.Result, error)
}

// Paths are the folders a file moves between. All must share a filesystem.
type Paths struct {
	DataDir    string // parent of Incoming, Quarantine and Tmp
	Incoming   string
	Quarantine string
	Tmp        string
	Outbox     string
}

// NewPaths derives the standard layout under dataDir.
func NewPaths(dataDir, outbox string) Paths {
	return Paths{
		DataDir:    dataDir,
		Incoming:   filepath.Join(dataDir, "incoming"),
		Quarantine: filepath.Join(dataDir, "quarantine"),
		Tmp:        filepath.Join(dataDir, "tmp"),
		Outbox:     outbox,
	}
}

// Prepare creates the folders, empties tmp, and refuses layouts in which
// renames would not be atomic or the diode could see staging files.
func (p Paths) Prepare() error {
	for _, d := range []string{p.Incoming, p.Quarantine, p.Tmp} {
		if err := os.MkdirAll(d, fsutil.DirMode); err != nil {
			return err
		}
		if err := tighten(d); err != nil {
			return err
		}
	}
	if _, err := os.Stat(p.Outbox); err != nil {
		return fmt.Errorf("outbox: %w", err)
	}
	for _, d := range []string{p.Incoming, p.Quarantine, p.Tmp} {
		if fsutil.IsWithin(p.Outbox, d) {
			return fmt.Errorf("%s is inside the outbox; the diode would collect staging files", d)
		}
	}
	if err := fsutil.SameDevice(p.Incoming, p.Quarantine, p.Tmp, p.Outbox); err != nil {
		return err
	}
	ents, err := os.ReadDir(p.Tmp)
	if err != nil {
		return err
	}
	for _, e := range ents {
		os.RemoveAll(filepath.Join(p.Tmp, e.Name()))
	}
	return nil
}

// tighten brings a staging folder made by an earlier version (0755, files
// 0644) down to DirMode and FileMode.
func tighten(dir string) error {
	if err := os.Chmod(dir, fsutil.DirMode); err != nil {
		return fmt.Errorf("%s: %w (the folder must belong to uid 65532)", dir, err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			if err := os.Chmod(filepath.Join(dir, e.Name()), fsutil.FileMode); err != nil {
				return err
			}
		}
	}
	return nil
}

// Pipeline owns the scan queue and everything that happens after a file is
// fully received.
type Pipeline struct {
	Store        *store.Store
	Audit        *audit.Log
	Scanner      Scanner
	Paths        Paths
	Policy       Policy
	ClamdPrefix  string // DataDir as clamd sees it
	ScanTimeout  time.Duration
	Concurrency  int
	UploadExpiry time.Duration
	Log          *slog.Logger

	queue   chan string
	qmu     sync.Mutex
	queued  map[string]bool
	closeMu sync.Mutex
	placeMu sync.Mutex
	waiting sync.Map // uploads already logged as waiting for an outbox name
	healthy atomic.Bool
	dbMu    sync.Mutex
	db      string
	now     func() time.Time
}

// Init must be called before Start or Enqueue.
func (p *Pipeline) Init() {
	p.queue = make(chan string, 10000)
	p.queued = map[string]bool{}
	if p.now == nil {
		p.now = func() time.Time { return time.Now().UTC() }
	}
	if p.Log == nil {
		p.Log = slog.Default()
	}
}

// Healthy reports whether clamd passed its most recent self-test.
func (p *Pipeline) Healthy() bool { return p.healthy.Load() }

// Start runs the self-test loop, scan workers and the janitor until ctx ends.
func (p *Pipeline) Start(ctx context.Context) {
	go p.healthLoop(ctx)
	for i := 0; i < p.Concurrency; i++ {
		go p.worker(ctx)
	}
	go p.janitorLoop(ctx)
}

// Enqueue schedules a completed upload for scanning. Duplicates are ignored;
// if the queue is full the janitor picks the upload up later.
func (p *Pipeline) Enqueue(id string) {
	p.qmu.Lock()
	defer p.qmu.Unlock()
	if p.queued[id] {
		return
	}
	select {
	case p.queue <- id:
		p.queued[id] = true
	default:
		p.Log.Warn("scan queue full; will retry", "upload", id)
	}
}

// QueueDepth is the number of uploads waiting or being scanned.
func (p *Pipeline) QueueDepth() int {
	p.qmu.Lock()
	defer p.qmu.Unlock()
	return len(p.queued)
}

func (p *Pipeline) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-p.queue:
			retry := p.process(ctx, id)
			p.qmu.Lock()
			delete(p.queued, id)
			p.qmu.Unlock()
			if retry {
				select {
				case <-ctx.Done():
					return
				case <-time.After(15 * time.Second):
				}
				p.Enqueue(id)
			}
		}
	}
}

// process scans one upload. It returns true if the scan should be retried
// later (scanner unavailable), leaving the upload in the scanning state.
func (p *Pipeline) process(ctx context.Context, id string) (retry bool) {
	u, err := p.Store.Upload(id)
	if err != nil {
		p.Log.Error("scan: load upload", "upload", id, "err", err)
		return false
	}
	if u.State != store.StateScanning {
		p.finish(u)
		return false
	}
	// Never scan with a scanner that has not proved it detects EICAR.
	for !p.Healthy() {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Second):
		}
	}

	in := filepath.Join(p.Paths.Incoming, id)
	fi, err := os.Stat(in)
	switch {
	case err != nil:
		p.decide(u, Decision{store.StateHeld, "staged file missing"}, clamd.Result{})
		return false
	case fi.Size() != u.Size:
		p.decide(u, Decision{store.StateHeld, fmt.Sprintf("staged file is %d bytes, expected %d", fi.Size(), u.Size)}, clamd.Result{})
		return false
	}

	sctx, cancel := context.WithTimeout(ctx, p.ScanTimeout)
	defer cancel()
	start := p.now()
	res, scanErr := p.Scanner.Scan(sctx, p.clamdPath(in))
	if ctx.Err() != nil {
		return false // shutting down; the upload is rescanned at startup
	}
	var opErr *net.OpError
	if errors.As(scanErr, &opErr) && opErr.Op == "dial" {
		p.Log.Warn("clamd unreachable; scan postponed", "upload", id, "err", scanErr)
		return true
	}
	dec := Classify(res, scanErr, u.Size, p.Policy)
	p.Log.Info("scanned", "upload", id, "verdict", res.Verdict, "state", dec.State, "seconds", p.now().Sub(start).Seconds())
	p.decide(u, dec, res)
	return false
}

func (p *Pipeline) clamdPath(local string) string {
	rel, err := filepath.Rel(p.Paths.DataDir, local)
	if err != nil {
		return local
	}
	return filepath.Join(p.ClamdPrefix, rel)
}

// decide records the decision first, then moves the file. If the process
// dies between the two, the janitor completes the move from the record.
func (p *Pipeline) decide(u store.Upload, dec Decision, res clamd.Result) {
	u, err := p.Store.UpdateUpload(u.ID, func(x *store.Upload) error {
		x.State = dec.State
		x.ScanReason = dec.Reason
		x.ScanResult = res.Verdict
		x.Signature = res.Signature
		x.ClamDB = p.dbVersion()
		x.ScannedAt = p.now()
		return nil
	})
	if err != nil {
		p.Log.Error("record scan decision", "upload", u.ID, "err", err)
		return
	}
	details := map[string]string{"state": string(dec.State), "sha256": u.SHA256, "size": fmt.Sprint(u.Size)}
	if dec.Reason != "" {
		details["reason"] = dec.Reason
	}
	p.auditEvent("system", "scanner", "upload."+string(dec.State), u, details)
	p.finish(u)
}

// Finish places a terminal upload's file (for example one the user
// cancelled) and closes its batch if ready.
func (p *Pipeline) Finish(u store.Upload) { p.finish(u) }

// finish places a terminal upload's file and closes its batch if ready.
// Placement is serialized and works from a fresh copy of the record, so a
// scan worker and the janitor can never move the same file at once.
func (p *Pipeline) finish(u store.Upload) {
	p.placeMu.Lock()
	fresh, err := p.Store.Upload(u.ID)
	if err != nil || !fresh.State.Terminal() {
		p.placeMu.Unlock()
		return
	}
	err = p.place(fresh)
	p.placeMu.Unlock()
	if errors.Is(err, errOutboxBusy) {
		// Retried by the janitor every few seconds; logged once per file.
		if _, seen := p.waiting.LoadOrStore(u.ID, true); !seen {
			p.Log.Info("waiting for the diode to collect a file with the same name", "upload", u.ID, "name", fresh.OutboxName)
		}
		return
	}
	p.waiting.Delete(u.ID)
	if err != nil {
		p.Log.Error("place file", "upload", u.ID, "state", fresh.State, "err", err)
		return
	}
	p.maybeCloseBatch(u.BatchID)
}

// place is idempotent: it can be re-run after a crash at any point.
func (p *Pipeline) place(u store.Upload) error {
	in := filepath.Join(p.Paths.Incoming, u.ID)
	if u.State == store.StateReleased {
		in = filepath.Join(p.Paths.Quarantine, u.ID)
	}
	_, statErr := os.Stat(in)
	staged := statErr == nil

	if !u.Placed {
		var err error
		switch u.State {
		case store.StatePassed, store.StateUnscanned, store.StateReleased:
			dest := filepath.Join(p.Paths.Outbox, u.OutboxName)
			if staged && p.occupied(in, dest) {
				err = os.ErrExist
			} else {
				if staged {
					// The diode reads as another user.
					if err := os.Chmod(in, fsutil.PublicFileMode); err != nil {
						return err
					}
				}
				err = p.move(in, dest, staged)
			}
			if errors.Is(err, os.ErrExist) {
				// An earlier file with the same name (or its sidecar) is still
				// in the outbox. Never overwrite something the diode may be
				// collecting: wait for it to go, and hold only if it stays.
				since := u.ScannedAt
				if u.State == store.StateReleased {
					since = u.ReleasedAt
				}
				if p.now().Sub(since) < OutboxWait {
					return errOutboxBusy
				}
				u, err = p.Store.UpdateUpload(u.ID, func(x *store.Upload) error {
					x.State = store.StateHeld
					x.ScanReason = "a file with the same name stayed in the outbox for over " + OutboxWait.String()
					return nil
				})
				if err != nil {
					return err
				}
				p.auditEvent("system", "outbox", "upload.held", u, map[string]string{"reason": u.ScanReason})
				return p.place(u)
			}
		case store.StateQuarantined, store.StateHeld:
			err = p.move(in, filepath.Join(p.Paths.Quarantine, u.ID), staged)
		case store.StateDeleted, store.StateExpired:
			if staged {
				err = os.Remove(in)
			}
		}
		if err != nil {
			return err
		}
		u, err = p.Store.UpdateUpload(u.ID, func(x *store.Upload) error { x.Placed = true; return nil })
		if err != nil {
			return err
		}
	}

	if u.State.InOutbox() && !u.SidecarDone {
		line := fmt.Sprintf("%s  %s\n", u.SHA256, u.OutboxName)
		dest := filepath.Join(p.Paths.Outbox, u.OutboxName+".sha256")
		if err := writeNoReplace(p.Paths.Tmp, dest, []byte(line), fsutil.PublicFileMode); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			// Ours from an interrupted earlier attempt, or an older file's
			// sidecar the diode has not collected yet.
			if have, _ := os.ReadFile(dest); string(have) != line {
				return errOutboxBusy
			}
		}
		var err error
		if u, err = p.Store.UpdateUpload(u.ID, func(x *store.Upload) error { x.SidecarDone = true; return nil }); err != nil {
			return err
		}
	}

	if u.State == store.StateReleased && !u.ManifestDone {
		if err := p.writeReleaseManifest(u); err != nil {
			return err
		}
		if _, err := p.Store.UpdateUpload(u.ID, func(x *store.Upload) error { x.ManifestDone = true; return nil }); err != nil {
			return err
		}
	}
	return nil
}

// OutboxWait is how long a file waits for an earlier file with the same
// name to leave the outbox before it is held instead.
const OutboxWait = time.Hour

var errOutboxBusy = errors.New("outbox name in use")

// occupied reports whether dest or its sidecar belongs to another file still
// in the outbox. A dest that is the same file as src is our own interrupted
// move, not a conflict.
func (p *Pipeline) occupied(src, dest string) bool {
	if b, err := os.Stat(dest); err == nil {
		if a, err := os.Stat(src); err != nil || !os.SameFile(a, b) {
			return true
		}
	}
	_, err := os.Lstat(dest + ".sha256")
	return err == nil
}

// writeNoReplace writes data to a temporary file in tmpDir and moves it to
// dest without ever replacing an existing file.
func writeNoReplace(tmpDir, dest string, data []byte, mode os.FileMode) error {
	tmp, err := fsutil.TempPath(tmpDir)
	if err != nil {
		return err
	}
	if err := fsutil.WriteAtomicMode(tmpDir, tmp, data, mode); err != nil {
		return err
	}
	if err := fsutil.MoveNoReplace(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// move renames src to dest without overwriting. If src is already gone the
// earlier attempt finished (or the diode collected the file), so it is done.
func (p *Pipeline) move(src, dest string, staged bool) error {
	if !staged {
		return nil
	}
	if b, err := os.Stat(dest); err == nil {
		a, err := os.Stat(src)
		if err != nil {
			return nil // already moved
		}
		// A crash between link and unlink leaves both; drop the staged
		// copy only if it is the same file.
		if os.SameFile(a, b) {
			return os.Remove(src)
		}
		return &os.LinkError{Op: "move", Old: src, New: dest, Err: os.ErrExist}
	}
	return fsutil.MoveNoReplace(src, dest)
}

type manifestFile struct {
	Name         string    `json:"name"`
	OriginalName string    `json:"original_name"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	ScanStatus   string    `json:"scan_status"` // clean | unscanned
	ScanReason   string    `json:"scan_reason,omitempty"`
	ClamDB       string    `json:"clamav_db,omitempty"`
	ScannedAt    time.Time `json:"scanned_at"`
}

type manifest struct {
	Schema        int            `json:"schema"`
	BatchID       string         `json:"batch_id"`
	Username      string         `json:"username"`
	CreatedAt     time.Time      `json:"created_at"`
	ClosedAt      time.Time      `json:"closed_at"`
	DeclaredCount int            `json:"file_count_declared"`
	Files         []manifestFile `json:"files"`
	WithheldCount int            `json:"withheld_count"`
	MissingCount  int            `json:"missing_count"`
	Release       *releaseInfo   `json:"release,omitempty"`
	AuditHead     audit.Head     `json:"audit_head"`
	Generator     string         `json:"generator"`
}

// releaseInfo is present only in the manifest written when an operator
// releases a held file after its batch has already closed.
type releaseInfo struct {
	UploadID   string    `json:"upload_id"`
	HeldReason string    `json:"held_reason"`
	ReleasedBy string    `json:"released_by"`
	Reason     string    `json:"reason"`
	ReleasedAt time.Time `json:"released_at"`
}

func fileEntry(u store.Upload) manifestFile {
	f := manifestFile{
		Name: u.OutboxName, OriginalName: u.OriginalName, Size: u.Size, SHA256: u.SHA256,
		ScanStatus: "clean", ClamDB: u.ClamDB, ScannedAt: u.ScannedAt,
	}
	switch u.State {
	case store.StateUnscanned:
		f.ScanStatus = "unscanned"
		f.ScanReason = u.ScanReason
	case store.StateReleased:
		f.ScanStatus = "released"
		f.ScanReason = fmt.Sprintf("held (%s); released by %s: %s", u.HeldReason, u.ReleasedBy, u.ReleaseReason)
	}
	return f
}

// writeReleaseManifest describes one released file whose batch manifest
// has already gone to the diode.
func (p *Pipeline) writeReleaseManifest(u store.Upload) error {
	b, err := p.Store.Batch(u.BatchID)
	if err != nil {
		return err
	}
	m := manifest{
		Schema: 1, BatchID: b.ID, Username: b.Username, CreatedAt: b.CreatedAt,
		ClosedAt: p.now(), DeclaredCount: 1, Files: []manifestFile{fileEntry(u)},
		Release: &releaseInfo{
			UploadID: u.ID, HeldReason: u.HeldReason, ReleasedBy: u.ReleasedBy,
			Reason: u.ReleaseReason, ReleasedAt: u.ReleasedAt,
		},
		AuditHead: p.Audit.Head(), Generator: "docker-secure-upload " + Version,
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	name := b.ID + ".release-" + u.ID[:8] + ".manifest.json"
	return fsutil.WriteAtomicMode(p.Paths.Tmp, filepath.Join(p.Paths.Outbox, name), append(data, '\n'), fsutil.PublicFileMode)
}

// Version is the service version written into manifests; main sets it.
var Version = "dev"

// maybeCloseBatch writes the manifest once every declared file has reached
// an end state and been placed, or once the batch has been open longer than
// the upload expiry (the client never sent the rest).
func (p *Pipeline) maybeCloseBatch(batchID string) {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	b, err := p.Store.Batch(batchID)
	if err != nil || !b.ClosedAt.IsZero() {
		return
	}
	ups := p.Store.BatchUploads(batchID)
	// A batch is abandoned once nothing has happened in it for the upload
	// expiry, so a slow multi-file batch is never closed under its sender.
	last := b.CreatedAt
	for _, u := range ups {
		if u.UpdatedAt.After(last) {
			last = u.UpdatedAt
		}
	}
	stale := p.now().Sub(last) > p.UploadExpiry
	if b.Created < b.FileCount && !stale {
		return
	}
	if b.Created == 0 {
		// Nothing was ever sent: drop the record rather than send the
		// diode an empty manifest (audit finding M-4).
		if _, err := p.Store.DeleteBatch(b.ID); err != nil {
			p.Log.Error("discard empty batch", "batch", b.ID, "err", err)
			return
		}
		_ = p.Audit.Append(audit.Event{
			ActorType: "system", Actor: "janitor", Action: "batch.discarded", BatchID: b.ID,
			Details: map[string]string{"reason": "no files were uploaded", "file_count_declared": fmt.Sprint(b.FileCount)},
		})
		return
	}
	m := manifest{
		Schema: 1, BatchID: b.ID, Username: b.Username, CreatedAt: b.CreatedAt,
		ClosedAt: p.now(), DeclaredCount: b.FileCount, Files: []manifestFile{},
		Generator: "docker-secure-upload " + Version,
	}
	for _, u := range ups {
		if !u.State.Terminal() || !u.Placed || (u.State.InOutbox() && !u.SidecarDone) {
			return
		}
		if !u.State.InOutbox() {
			m.WithheldCount++
			continue
		}
		m.Files = append(m.Files, fileEntry(u))
	}
	if b.FileCount > b.Created {
		m.MissingCount = b.FileCount - b.Created
	}
	m.AuditHead = p.Audit.Head()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		p.Log.Error("manifest encode", "batch", b.ID, "err", err)
		return
	}
	name := b.ID + ".manifest.json"
	if err := fsutil.WriteAtomicMode(p.Paths.Tmp, filepath.Join(p.Paths.Outbox, name), append(data, '\n'), fsutil.PublicFileMode); err != nil {
		p.Log.Error("manifest write", "batch", b.ID, "err", err)
		return
	}
	if _, err := p.Store.UpdateBatch(b.ID, func(x *store.Batch) error {
		x.ClosedAt = m.ClosedAt
		x.ManifestName = name
		return nil
	}); err != nil {
		p.Log.Error("batch close", "batch", b.ID, "err", err)
		return
	}
	_ = p.Audit.Append(audit.Event{
		ActorType: "system", Actor: "outbox", Action: "batch.closed", BatchID: b.ID,
		Details: map[string]string{
			"manifest": name, "passed": fmt.Sprint(len(m.Files)),
			"withheld": fmt.Sprint(m.WithheldCount), "missing": fmt.Sprint(m.MissingCount),
		},
	})
	p.Log.Info("batch closed", "batch", b.ID, "files", len(m.Files), "withheld", m.WithheldCount)
}

func (p *Pipeline) auditEvent(actorType, actor, action string, u store.Upload, details map[string]string) {
	if err := p.Audit.Append(audit.Event{
		ActorType: actorType, Actor: actor, Action: action,
		UploadID: u.ID, BatchID: u.BatchID, Details: details,
	}); err != nil {
		p.Log.Error("audit append", "action", action, "err", err)
	}
}

func (p *Pipeline) dbVersion() string {
	p.dbMu.Lock()
	defer p.dbMu.Unlock()
	return p.db
}

// healthLoop waits for clamd, proves it detects EICAR, and repeats hourly.
// Workers do not scan while the scanner is unproven.
func (p *Pipeline) healthLoop(ctx context.Context) {
	wait := 5 * time.Second
	for {
		err := p.selfTest(ctx)
		if err != nil {
			if p.healthy.Swap(false) || wait == 5*time.Second {
				p.Log.Warn("clamd self-test failed; scanning paused", "err", err)
			}
		} else if !p.healthy.Swap(true) {
			p.Log.Info("clamd self-test passed; scanning enabled", "db", p.dbVersion())
		}
		next := time.Hour
		if err != nil {
			next = wait
			wait = min(wait*2, time.Minute)
		} else {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

func (p *Pipeline) selfTest(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := p.Scanner.Ping(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	if v, err := p.Scanner.Version(ctx); err == nil {
		p.dbMu.Lock()
		p.db = fmt.Sprintf("%s/%d", v.Engine, v.DBVersion)
		p.dbMu.Unlock()
	}
	path, err := fsutil.TempPath(p.Paths.Tmp)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, clamd.EICAR(), fsutil.FileMode); err != nil {
		return err
	}
	defer os.Remove(path)
	res, err := p.Scanner.Scan(ctx, p.clamdPath(path))
	if err != nil {
		return fmt.Errorf("EICAR scan: %w", err)
	}
	if res.Verdict != clamd.VerdictFound {
		return fmt.Errorf("EICAR test file not detected (verdict %q)", res.Verdict)
	}
	return nil
}

func (p *Pipeline) janitorLoop(ctx context.Context) {
	// Every 10 seconds, so files waiting for a name to clear move soon
	// after the diode collects the earlier file (2 s settle time).
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	p.Janitor()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Janitor()
		}
	}
}

// Janitor expires abandoned uploads, requeues interrupted scans, finishes
// interrupted moves and closes batches that are ready.
func (p *Pipeline) Janitor() {
	for _, u := range p.Store.UploadsIn(store.StateReceiving) {
		if p.now().Sub(u.UpdatedAt) < p.UploadExpiry {
			continue
		}
		nu, err := p.Store.UpdateUpload(u.ID, func(x *store.Upload) error {
			if x.State != store.StateReceiving {
				return errors.New("state changed")
			}
			x.State = store.StateExpired
			x.ScanReason = "upload not completed in time"
			return nil
		})
		if err != nil {
			continue
		}
		p.auditEvent("system", "janitor", "upload.expired", nu, map[string]string{"received": fmt.Sprint(u.Offset), "size": fmt.Sprint(u.Size)})
		p.finish(nu)
	}
	for _, u := range p.Store.UploadsIn(store.StateScanning) {
		p.Enqueue(u.ID)
	}
	for _, u := range p.Store.UploadsIn(store.StatePassed, store.StateUnscanned, store.StateQuarantined,
		store.StateHeld, store.StateDeleted, store.StateExpired, store.StateReleased) {
		if !u.Placed || (u.State.InOutbox() && !u.SidecarDone) || (u.State == store.StateReleased && !u.ManifestDone) {
			p.finish(u)
		}
	}
	for _, b := range p.Store.OpenBatches() {
		p.maybeCloseBatch(b.ID)
	}
}
