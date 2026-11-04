package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

type fakeOps struct{ released, deleted string }

func (f *fakeOps) Withheld() []store.Upload {
	return []store.Upload{{ID: "abc", State: store.StateHeld, ScanReason: "too large to scan", Size: 5}}
}

func (f *fakeOps) Release(id, by, reason string) (store.Upload, error) {
	if id != "abc" {
		return store.Upload{}, store.ErrNotFound
	}
	f.released = by + ":" + reason
	return store.Upload{ID: id, State: store.StateReleased, OutboxName: "x.bin"}, nil
}

func (f *fakeOps) Discard(id, by, reason string) (store.Upload, error) {
	return store.Upload{}, errors.New("infected files cannot be released")
}

func TestRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "c.sock")
	ops := &fakeOps{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, sock, ops, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	c := NewClient(sock)
	items, err := c.Held()
	if err != nil || len(items) != 1 || items[0].Reason != "too large to scan" {
		t.Fatalf("held: %v %v", items, err)
	}
	it, err := c.Release(Request{ID: "abc", By: "ops", Reason: "checked"})
	if err != nil || it.State != "released" || ops.released != "ops:checked" {
		t.Fatalf("release: %+v %v", it, err)
	}
	if _, err := c.Release(Request{ID: "nope", By: "a", Reason: "b"}); err == nil {
		t.Fatal("unknown id released")
	}
	if _, err := c.Delete(Request{ID: "abc", By: "a", Reason: "b"}); err == nil || !strings.Contains(err.Error(), "infected") {
		t.Fatalf("delete error not passed through: %v", err)
	}
}
