// Package audit writes an append-only, hash-chained event log.
//
// Each event stores the hash of the previous event and its own hash over
// its content, so removing, reordering or editing a line breaks the chain
// and Verify reports where. Files rotate daily (audit-YYYY-MM-DD.jsonl) so
// retention can delete whole days; pruning is added with the admin stage.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/fsutil"
)

// Event is one audit record.
type Event struct {
	Seq       uint64            `json:"seq"`
	Time      time.Time         `json:"ts"`
	ActorType string            `json:"actor_type"` // user | admin | system
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	UploadID  string            `json:"upload_id,omitempty"`
	BatchID   string            `json:"batch_id,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Log is safe for concurrent use.
type Log struct {
	dir      string
	mu       sync.Mutex
	seq      uint64
	prevHash string
	now      func() time.Time
}

// Open prepares the log in dir and resumes the chain from the last event.
func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, fsutil.DirMode); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, prevHash: genesis, now: func() time.Time { return time.Now().UTC() }}
	files, err := l.files()
	if err != nil {
		return nil, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		last, err := lastEvent(files[i])
		if err != nil {
			return nil, err
		}
		if last != nil {
			l.seq = last.Seq
			l.prevHash = last.Hash
			break
		}
	}
	return l, nil
}

func (l *Log) files() ([]string, error) {
	m, err := filepath.Glob(filepath.Join(l.dir, "audit-*.jsonl"))
	sort.Strings(m)
	return m, err
}

func lastEvent(path string) (*Event, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimRight(b, "\n")
	if len(b) == 0 {
		return nil, nil
	}
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("%s: last line: %w", path, err)
	}
	return &e, nil
}

// hashOf computes the event hash over every field except Hash.
func hashOf(e Event) string {
	e.Hash = ""
	b, _ := json.Marshal(e) // struct with string/map fields cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Head identifies the newest event in the chain. Copied into each batch
// manifest, it lets the receiving side detect a later rewrite of the log on
// the upload host (audit finding L-1).
type Head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// Head returns the newest event's sequence number and hash.
func (l *Log) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Head{Seq: l.seq, Hash: l.prevHash}
}

// Append chains, writes and fsyncs one event.
func (l *Log) Append(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = l.seq + 1
	e.Time = l.now()
	e.PrevHash = l.prevHash
	e.Hash = hashOf(e)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	name := filepath.Join(l.dir, "audit-"+e.Time.Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	l.seq = e.Seq
	l.prevHash = e.Hash
	return nil
}

// Verify checks the whole chain across all files and returns the number of
// events checked. The first event may follow a pruned prefix, so its
// PrevHash is accepted as the starting point.
func Verify(dir string) (int, error) {
	if _, err := os.Stat(dir); err != nil {
		return 0, err
	}
	l := &Log{dir: dir}
	files, err := l.files()
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, errors.New("no audit files found")
	}
	n := 0
	var prev string
	var seq uint64
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return n, err
		}
		r := bufio.NewReader(f)
		for {
			line, err := r.ReadBytes('\n')
			if len(strings.TrimSpace(string(line))) > 0 {
				var e Event
				if jerr := json.Unmarshal(line, &e); jerr != nil {
					f.Close()
					return n, fmt.Errorf("%s: unreadable event after seq %d: %w", path, seq, jerr)
				}
				if n > 0 && (e.PrevHash != prev || e.Seq != seq+1) {
					f.Close()
					return n, fmt.Errorf("%s: chain broken at seq %d", path, e.Seq)
				}
				if hashOf(e) != e.Hash {
					f.Close()
					return n, fmt.Errorf("%s: event seq %d was modified", path, e.Seq)
				}
				prev, seq = e.Hash, e.Seq
				n++
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				f.Close()
				return n, err
			}
		}
		f.Close()
	}
	return n, nil
}
