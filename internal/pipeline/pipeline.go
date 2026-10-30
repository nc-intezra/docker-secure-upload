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
	if err != nil {
		p.Log.Error("place file", "upload", u.ID, "state", fresh.State, "err", err)
		return
	}
	p.maybeCloseBatch(u.BatchID)
}

// place is idempotent: it can be re-run after a crash at any point.
func (p *Pipeline) place(u store.Upload) error {
	in := filepath.Join(p.Paths.Incoming, u.ID)
	_, statErr := os.Stat(in)
	staged := statErr == nil

	if !u.Placed {
		var err error
		switch u.State {
		case store.StatePassed, store.StateUnscanned:
			dest := filepath.Join(p.Paths.Outbox, u.OutboxName)
			err = p.move(in, dest, staged)
			if errors.Is(err, os.ErrExist) {
				// Another file already has this name: never overwrite
				// something the diode may be collecting. Hold instead.
				u, err = p.Store.UpdateUpload(u.ID, func(x *store.Upload) error {
					x.State = store.StateHeld
					x.ScanReason = "outbox name already in use"
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
		if err := fsutil.WriteAtomic(p.Paths.Tmp, dest, []byte(line)); err != nil {
			return err
		}
		if _, err := p.Store.UpdateUpload(u.ID, func(x *store.Upload) error { x.SidecarDone = true; return nil }); err != nil {
			return err
		}
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
	Generator     string         `json:"generator"`
}

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
	stale := p.now().Sub(b.CreatedAt) > p.UploadExpiry
	if b.Created < b.FileCount && !stale {
		return
	}
	m := manifest{
		Schema: 1, BatchID: b.ID, Username: b.Username, CreatedAt: b.CreatedAt,
		ClosedAt: p.now(), DeclaredCount: b.FileCount, Files: []manifestFile{},
		Generator: "docker-secure-upload",
	}
	for _, u := range ups {
		if !u.State.Terminal() || !u.Placed || (u.State.InOutbox() && !u.SidecarDone) {
			return
		}
		if !u.State.InOutbox() {
			m.WithheldCount++
			continue
		}
		f := manifestFile{
			Name: u.OutboxName, OriginalName: u.OriginalName, Size: u.Size, SHA256: u.SHA256,
			ScanStatus: "clean", ClamDB: u.ClamDB, ScannedAt: u.ScannedAt,
		}
		if u.State == store.StateUnscanned {
			f.ScanStatus = "unscanned"
			f.ScanReason = u.ScanReason
		}
		m.Files = append(m.Files, f)
	}
	if b.FileCount > b.Created {
		m.MissingCount = b.FileCount - b.Created
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		p.Log.Error("manifest encode", "batch", b.ID, "err", err)
		return
	}
	name := b.ID + ".manifest.json"
	if err := fsutil.WriteAtomic(p.Paths.Tmp, filepath.Join(p.Paths.Outbox, name), append(data, '\n')); err != nil {
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
	t := time.NewTicker(time.Minute)
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
		store.StateHeld, store.StateDeleted, store.StateExpired) {
		if !u.Placed || (u.State.InOutbox() && !u.SidecarDone) {
			p.finish(u)
		}
	}
	for _, b := range p.Store.OpenBatches() {
		p.maybeCloseBatch(b.ID)
	}
}
