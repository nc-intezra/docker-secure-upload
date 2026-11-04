package limits

import (
	"errors"
	"testing"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/config"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

func TestCaps(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{
		Session: config.Limits{OpenBatches: 1, OpenUploads: 2, Reserved: 100},
		IP:      config.Limits{OpenBatches: 2, OpenUploads: 3, Reserved: 150},
		Store:   st,
	}
	now := time.Now().UTC()
	mkBatch := func(id, sess, ip string) error {
		return c.Batch(sess, ip, func() error {
			return st.CreateBatch(store.Batch{ID: id, SessionHash: sess, ClientIP: ip, FileCount: 10, CreatedAt: now})
		})
	}
	var le *Error
	if err := mkBatch("b1", "s1", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := mkBatch("b2", "s1", "10.0.0.1"); !errors.As(err, &le) {
		t.Fatalf("second batch in one session: %v", err)
	}
	if err := mkBatch("b3", "s2", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := mkBatch("b4", "s3", "10.0.0.1"); !errors.As(err, &le) {
		t.Fatalf("third batch from one address: %v", err)
	}

	n := 0
	mkUpload := func(batch, sess string, size int64) error {
		return c.Upload(sess, "10.0.0.1", size, func() error {
			n++
			_, err := st.CreateUpload(store.Upload{
				ID: string(rune('a'+n)) + "x", BatchID: batch, SessionHash: sess, ClientIP: "10.0.0.1",
				Size: size, State: store.StateReceiving, CreatedAt: now,
			}, func(*store.Batch, *store.Upload, int) error { return nil })
			return err
		})
	}
	if err := mkUpload("b1", "s1", 60); err != nil {
		t.Fatal(err)
	}
	if err := mkUpload("b1", "s1", 60); !errors.As(err, &le) {
		t.Fatalf("session reservation: %v", err)
	}
	if err := mkUpload("b1", "s1", 40); err != nil {
		t.Fatal(err)
	}
	if err := mkUpload("b1", "s1", 0); !errors.As(err, &le) {
		t.Fatalf("session open uploads: %v", err)
	}
	if err := mkUpload("b3", "s2", 60); !errors.As(err, &le) {
		t.Fatalf("address reservation: %v", err)
	}
	if err := mkUpload("b3", "s2", 50); err != nil {
		t.Fatal(err)
	}
}
