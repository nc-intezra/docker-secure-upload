// Package store keeps batch and upload records as one JSON file each under
// the state directory, with an in-memory index. At under 50 users and a
// 90-day retention this is a few tens of thousands of small files, which
// is well within what a single process can index at startup.
//
// Every write goes through fsutil.WriteAtomic, so a record on disk is always
// complete.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/fsutil"
)

// State is an upload's position in its lifecycle.
type State string

const (
	StateReceiving   State = "receiving"   // chunks still arriving
	StateScanning    State = "scanning"    // complete, queued for or in scan
	StatePassed      State = "passed"      // clean, in the outbox
	StateUnscanned   State = "unscanned"   // in the outbox, flagged not fully scanned
	StateQuarantined State = "quarantined" // infected, in quarantine/
	StateDeleted     State = "deleted"     // infected with quarantine off, removed
	StateHeld        State = "held"        // scan error or archive limit, in quarantine/
	StateExpired     State = "expired"     // abandoned or aged out, removed
)

// Terminal reports whether no further automatic transition will happen.
func (s State) Terminal() bool {
	switch s {
	case StateReceiving, StateScanning:
		return false
	}
	return true
}

// InOutbox reports whether the file was handed to the diode.
func (s State) InOutbox() bool { return s == StatePassed || s == StateUnscanned }

// Batch groups the files one user sent in one go.
type Batch struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	ClientIP     string    `json:"client_ip"`
	SessionHash  string    `json:"session_hash"` // SHA-256 of the session ID
	FileCount    int       `json:"file_count"`   // files the client declared
	Created      int       `json:"created"`      // uploads created so far
	CreatedAt    time.Time `json:"created_at"`
	ClosedAt     time.Time `json:"closed_at,omitzero"`
	ManifestName string    `json:"manifest_name,omitempty"`
}

// Upload is one file.
type Upload struct {
	ID           string    `json:"id"` // random hex; also the name in incoming/ and quarantine/
	BatchID      string    `json:"batch_id"`
	Seq          int       `json:"seq"`
	Username     string    `json:"username"`
	ClientIP     string    `json:"client_ip"`
	SessionHash  string    `json:"session_hash"`
	OriginalName string    `json:"original_name"`
	OutboxName   string    `json:"outbox_name"`
	Size         int64     `json:"size"`
	Offset       int64     `json:"offset"`
	HashState    []byte    `json:"hash_state,omitempty"` // saved SHA-256 state at Offset
	SHA256       string    `json:"sha256,omitempty"`
	State        State     `json:"state"`
	ScanResult   string    `json:"scan_result,omitempty"` // raw clamd verdict class
	Signature    string    `json:"signature,omitempty"`   // admin-only detail
	ScanReason   string    `json:"scan_reason,omitempty"`
	ClamDB       string    `json:"clamav_db,omitempty"`
	Placed       bool      `json:"placed,omitempty"`       // file moved to its end-state location
	SidecarDone  bool      `json:"sidecar_done,omitempty"` // .sha256 written to the outbox
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	CompletedAt  time.Time `json:"completed_at,omitzero"`
	ScannedAt    time.Time `json:"scanned_at,omitzero"`
}

// ErrNotFound is returned for unknown IDs.
var ErrNotFound = errors.New("not found")

var idPattern = regexp.MustCompile(`^[0-9A-Za-z._-]{1,96}$`)

// Store is safe for concurrent use.
type Store struct {
	dir     string
	tmp     string
	mu      sync.Mutex
	batches map[string]*Batch
	uploads map[string]*Upload
}

// Open loads every record under dir, creating the layout if needed.
func Open(dir string) (*Store, error) {
	s := &Store{
		dir:     dir,
		tmp:     filepath.Join(dir, "tmp"),
		batches: map[string]*Batch{},
		uploads: map[string]*Upload{},
	}
	for _, sub := range []string{"batches", "uploads", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), fsutil.DirMode); err != nil {
			return nil, err
		}
	}
	if err := clearDir(s.tmp); err != nil {
		return nil, err
	}
	if err := loadAll(filepath.Join(dir, "batches"), func(b []byte) error {
		var v Batch
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		s.batches[v.ID] = &v
		return nil
	}); err != nil {
		return nil, err
	}
	if err := loadAll(filepath.Join(dir, "uploads"), func(b []byte) error {
		var v Upload
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		s.uploads[v.ID] = &v
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

func clearDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func loadAll(dir string, fn func([]byte) error) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if err := fn(b); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	return nil
}

func (s *Store) write(kind, id string, v any) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("invalid record id %q", id)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(s.tmp, filepath.Join(s.dir, kind, id+".json"), b)
}

func (s *Store) remove(kind, id string) error {
	err := os.Remove(filepath.Join(s.dir, kind, id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// CreateBatch stores a new batch.
func (s *Store) CreateBatch(b Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.batches[b.ID]; ok {
		return fmt.Errorf("batch %s exists", b.ID)
	}
	if err := s.write("batches", b.ID, &b); err != nil {
		return err
	}
	s.batches[b.ID] = &b
	return nil
}

// Batch returns a copy of the batch.
func (s *Store) Batch(id string) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.batches[id]
	if !ok {
		return Batch{}, ErrNotFound
	}
	return *b, nil
}

// UpdateBatch applies fn to a copy and persists it if fn returns nil.
func (s *Store) UpdateBatch(id string, fn func(*Batch) error) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.batches[id]
	if !ok {
		return Batch{}, ErrNotFound
	}
	next := *cur
	if err := fn(&next); err != nil {
		return Batch{}, err
	}
	if err := s.write("batches", id, &next); err != nil {
		return Batch{}, err
	}
	s.batches[id] = &next
	return next, nil
}

// CreateUpload stores a new upload and bumps its batch's created count in
// one step, so concurrent creations cannot exceed the declared file count.
// prepare runs under the store lock with the batch as it stands and the
// sequence number the upload will get; it may reject or fill in u.
func (s *Store) CreateUpload(u Upload, prepare func(b *Batch, u *Upload, seq int) error) (Upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.batches[u.BatchID]
	if !ok {
		return Upload{}, ErrNotFound
	}
	if _, exists := s.uploads[u.ID]; exists {
		return Upload{}, fmt.Errorf("upload %s exists", u.ID)
	}
	nb := *b
	seq := nb.Created + 1
	if err := prepare(&nb, &u, seq); err != nil {
		return Upload{}, err
	}
	nb.Created = seq
	u.Seq = seq
	if err := s.write("uploads", u.ID, &u); err != nil {
		return Upload{}, err
	}
	if err := s.write("batches", nb.ID, &nb); err != nil {
		_ = s.remove("uploads", u.ID)
		return Upload{}, err
	}
	s.batches[nb.ID] = &nb
	s.uploads[u.ID] = &u
	return u, nil
}

// Upload returns a copy of the upload.
func (s *Store) Upload(id string) (Upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.uploads[id]
	if !ok {
		return Upload{}, ErrNotFound
	}
	return *u, nil
}

// UpdateUpload applies fn to a copy and persists it if fn returns nil.
func (s *Store) UpdateUpload(id string, fn func(*Upload) error) (Upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.uploads[id]
	if !ok {
		return Upload{}, ErrNotFound
	}
	next := *cur
	if err := fn(&next); err != nil {
		return Upload{}, err
	}
	next.UpdatedAt = time.Now().UTC()
	if err := s.write("uploads", id, &next); err != nil {
		return Upload{}, err
	}
	s.uploads[id] = &next
	return next, nil
}

// BatchUploads returns the batch's uploads ordered by sequence number.
func (s *Store) BatchUploads(batchID string) []Upload {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Upload
	for _, u := range s.uploads {
		if u.BatchID == batchID {
			out = append(out, *u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// UploadsIn returns uploads in any of the given states, oldest first.
func (s *Store) UploadsIn(states ...State) []Upload {
	want := map[State]bool{}
	for _, st := range states {
		want[st] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Upload
	for _, u := range s.uploads {
		if want[u.State] {
			out = append(out, *u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// OpenBatches returns batches without a manifest yet.
func (s *Store) OpenBatches() []Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Batch
	for _, b := range s.batches {
		if b.ClosedAt.IsZero() {
			out = append(out, *b)
		}
	}
	return out
}
