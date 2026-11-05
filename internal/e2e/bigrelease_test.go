package e2e

import (
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/pipeline"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
	"github.com/nc-intezra/docker-secure-upload/internal/tus"
	"github.com/nc-intezra/docker-secure-upload/internal/web"
)

func TestBigRelease(t *testing.T) {
	if os.Getenv("BIG") == "" {
		t.Skip("set BIG=1")
	}
	const chunk = 64 << 20
	const size = 2100 << 20
	e := newEnv(t, true, holdPolicy, func(p *pipeline.Pipeline, h *tus.Handler, s *web.Server) {
		h.MaxFileSize, h.ChunkSize, s.MaxFileSize, s.ChunkSize = 3<<30, chunk, 3<<30, chunk
		p.ScanTimeout = 5 * time.Minute
	})
	c := e.newClient()
	b := c.batch("big", 1)
	loc, code := c.create(b, "big.bin", size)
	if code != 201 {
		t.Fatal(code)
	}
	r := rand.New(rand.NewPCG(1, 2))
	buf := make([]byte, chunk)
	for off := 0; off < size; off += chunk {
		n := min(chunk, size-off)
		for i := 0; i < n; i += 8 {
			v := r.Uint64()
			for j := 0; j < 8 && i+j < n; j++ {
				buf[i+j] = byte(v >> (8 * j))
			}
		}
		res := c.patch(loc, off, buf[:n])
		res.Body.Close()
		if res.StatusCode != 204 {
			t.Fatalf("PATCH %d: %d", off, res.StatusCode)
		}
	}
	id := idOf(loc)
	deadline := time.Now().Add(3 * time.Minute)
	for {
		u, _ := e.pipe.Store.Upload(id)
		if u.State.Terminal() && u.Placed {
			t.Logf("state %s placed %v reason %q", u.State, u.Placed, u.ScanReason)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stuck: %+v", u)
		}
		time.Sleep(200 * time.Millisecond)
	}
	start := time.Now()
	u, err := e.pipe.Release(id, "ops", "test")
	t.Logf("release took %v: %+v err=%v", time.Since(start), u.State, err)
	if err != nil || u.State != store.StateReleased {
		t.Fatal(err)
	}
}
