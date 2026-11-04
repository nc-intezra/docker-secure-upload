package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/clamd"
	"github.com/nc-intezra/docker-secure-upload/internal/config"
	"github.com/nc-intezra/docker-secure-upload/internal/limits"
	"github.com/nc-intezra/docker-secure-upload/internal/pipeline"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
	"github.com/nc-intezra/docker-secure-upload/internal/tus"
	"github.com/nc-intezra/docker-secure-upload/internal/web"
)

func holdPolicy(p *pipeline.Pipeline, _ *tus.Handler, _ *web.Server) {
	p.Policy.Oversize = config.OversizeHold
}

func idOf(loc string) string { return loc[strings.LastIndex(loc, "/")+1:] }

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// With OVERSIZE_POLICY=hold a file too large to scan is held, never sent,
// until an operator releases it. Infected files can never be released.
func TestHoldAndRelease(t *testing.T) {
	e := newEnv(t, true, holdPolicy)
	c := e.newClient()
	big := bytes.Repeat([]byte("B"), maxScan+10)
	infected := append([]byte("x "), clamd.EICAR()...)
	small := []byte("small and clean")

	b := c.batch("dave", 3)
	locBig, _ := c.create(b, "disk.img", len(big))
	c.upload(locBig, big)
	locBad, _ := c.create(b, "bad.exe", len(infected))
	c.upload(locBad, infected)
	locOK, _ := c.create(b, "ok.txt", len(small))
	c.upload(locOK, small)
	s := c.waitClosed(b)
	got := map[string]string{}
	for _, f := range s.Files {
		got[f.Name] = f.State
	}
	if got["disk.img"] != "held" || got["bad.exe"] != "blocked" || got["ok.txt"] != "sent" {
		t.Fatalf("states %v", got)
	}
	if _, err := os.Stat(filepath.Join(e.paths.Outbox, "disk.img")); err == nil {
		t.Fatal("oversize file reached the outbox under the hold policy")
	}

	// Modes: private in quarantine, readable by the diode in the outbox.
	if m := mode(t, filepath.Join(e.paths.Quarantine, idOf(locBig))); m != 0o640 {
		t.Errorf("quarantine file mode %o", m)
	}
	for _, n := range []string{"ok.txt", "ok.txt.sha256", b + ".manifest.json"} {
		if m := mode(t, filepath.Join(e.paths.Outbox, n)); m != 0o644 {
			t.Errorf("%s mode %o", n, m)
		}
	}
	var man struct {
		Withheld  int `json:"withheld_count"`
		AuditHead struct {
			Seq  uint64 `json:"seq"`
			Hash string `json:"hash"`
		} `json:"audit_head"`
		Files []struct {
			Name, ScanStatus string
		} `json:"files"`
	}
	raw, _ := os.ReadFile(filepath.Join(e.paths.Outbox, b+".manifest.json"))
	if err := json.Unmarshal(raw, &man); err != nil || man.Withheld != 2 || man.AuditHead.Seq == 0 || len(man.AuditHead.Hash) != 64 {
		t.Fatalf("manifest %s (%v)", raw, err)
	}

	// Refusals: infected, missing name or reason, tampered file.
	if _, err := e.pipe.Release(idOf(locBad), "ops", "looks fine"); err == nil {
		t.Fatal("infected file released")
	}
	if _, err := e.pipe.Release(idOf(locBig), "", "x"); err == nil {
		t.Fatal("release without a name accepted")
	}
	held := filepath.Join(e.paths.Quarantine, idOf(locBig))
	orig, _ := os.ReadFile(held)
	os.WriteFile(held, append([]byte("tampered"), orig...), 0o640)
	if _, err := e.pipe.Release(idOf(locBig), "ops", "checked offline"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered file released: %v", err)
	}
	os.WriteFile(held, orig, 0o640)

	u, err := e.pipe.Release(idOf(locBig), "ops", "checked offline")
	if err != nil {
		t.Fatal(err)
	}
	if u.State != store.StateReleased || !u.Placed || !u.SidecarDone || !u.ManifestDone {
		t.Fatalf("after release: %+v", u)
	}
	out := filepath.Join(e.paths.Outbox, "disk.img")
	if data, _ := os.ReadFile(out); !bytes.Equal(data, big) || mode(t, out) != 0o644 {
		t.Fatal("released file not in outbox, or wrong mode")
	}
	if side, _ := os.ReadFile(out + ".sha256"); string(side) != sha(big)+"  disk.img\n" {
		t.Fatalf("sidecar %q", side)
	}
	rel, _ := filepath.Glob(filepath.Join(e.paths.Outbox, b+".release-*.manifest.json"))
	if len(rel) != 1 {
		t.Fatalf("release manifests: %v", rel)
	}
	raw, _ = os.ReadFile(rel[0])
	for _, want := range []string{`"scan_status": "released"`, `"released_by": "ops"`, `"audit_head"`, `"name": "disk.img"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("release manifest lacks %s: %s", want, raw)
		}
	}
	res := c.do("GET", "/api/v1/batches/"+b, nil, nil)
	var st status
	json.NewDecoder(res.Body).Decode(&st)
	res.Body.Close()
	for _, f := range st.Files {
		if f.Name == "disk.img" && f.State != "sent" {
			t.Fatalf("user sees %s after release", f.State)
		}
	}
	if _, err := e.pipe.Release(idOf(locBig), "ops", "again"); err == nil {
		t.Fatal("released twice")
	}

	// Delete the infected file now.
	if _, err := e.pipe.Discard(idOf(locBad), "ops", "known test file"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.paths.Quarantine, idOf(locBad))); err == nil {
		t.Fatal("discarded file still in quarantine")
	}
	if len(e.pipe.Withheld()) != 0 {
		t.Fatalf("still withheld: %v", e.pipe.Withheld())
	}
}

// A file released while its batch is still open is listed in the batch
// manifest; no separate manifest is written.
func TestReleaseBeforeBatchCloses(t *testing.T) {
	e := newEnv(t, true, holdPolicy)
	c := e.newClient()
	big := bytes.Repeat([]byte("B"), maxScan+1)
	b := c.batch("erin", 2)
	loc, _ := c.create(b, "big.bin", len(big))
	c.upload(loc, big)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if u, _ := e.pipe.Store.Upload(idOf(loc)); u.State == store.StateHeld && u.Placed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not held")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := e.pipe.Release(idOf(loc), "ops", "ok"); err != nil {
		t.Fatal(err)
	}
	loc2, _ := c.create(b, "second.txt", 3)
	c.upload(loc2, []byte("abc"))
	c.waitClosed(b)
	raw, _ := os.ReadFile(filepath.Join(e.paths.Outbox, b+".manifest.json"))
	if !strings.Contains(string(raw), `"name": "big.bin"`) || !strings.Contains(string(raw), `"withheld_count": 0`) {
		t.Fatalf("batch manifest: %s", raw)
	}
	if rel, _ := filepath.Glob(filepath.Join(e.paths.Outbox, "*.release-*")); len(rel) != 0 {
		t.Fatalf("unexpected release manifest %v", rel)
	}
}

func TestLimits(t *testing.T) {
	e := newEnv(t, true, func(p *pipeline.Pipeline, h *tus.Handler, s *web.Server) {
		c := &limits.Checker{
			Session: config.Limits{OpenBatches: 2, OpenUploads: 1, Reserved: 1000},
			IP:      config.Limits{OpenBatches: 3, OpenUploads: 10, Reserved: 1 << 20},
			Store:   p.Store,
		}
		h.Limits, s.Limits = c, c
	})
	c := e.newClient()
	b := c.batch("frank", 5)
	if _, code := c.create(b, "a", 2000); code != 429 {
		t.Fatalf("over the reservation cap: %d", code)
	}
	loc, code := c.create(b, "a", 500)
	if code != 201 {
		t.Fatalf("first upload: %d", code)
	}
	if _, code := c.create(b, "b", 10); code != 429 {
		t.Fatalf("second open upload: %d", code)
	}
	c.upload(loc, bytes.Repeat([]byte("a"), 500)) // no longer open
	if _, code := c.create(b, "b", 10); code != 201 {
		t.Fatalf("after the first finished: %d", code)
	}

	c.batch("frank", 1)
	res := c.do("POST", "/api/v1/batches", strings.NewReader(`{"username":"frank","file_count":1}`),
		map[string]string{"Content-Type": "application/json"})
	res.Body.Close()
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("third open batch in one session: %d", res.StatusCode)
	}
	// A fresh session from the same address gets one more, then the
	// address cap applies.
	c2 := e.newClient()
	c2.batch("frank", 1)
	res = c2.do("POST", "/api/v1/batches", strings.NewReader(`{"username":"frank","file_count":1}`),
		map[string]string{"Content-Type": "application/json"})
	res.Body.Close()
	if res.StatusCode != 429 {
		t.Fatalf("fourth open batch from one address: %d", res.StatusCode)
	}
}

// A batch nobody uploads to is deleted after the idle expiry instead of
// producing an empty manifest.
func TestEmptyBatchDiscarded(t *testing.T) {
	e := newEnv(t, true, func(p *pipeline.Pipeline, _ *tus.Handler, _ *web.Server) {
		p.UploadExpiry = 100 * time.Millisecond
	})
	c := e.newClient()
	b := c.batch("gina", 3)
	time.Sleep(200 * time.Millisecond)
	e.pipe.Janitor()
	if _, err := e.pipe.Store.Batch(b); err == nil {
		t.Fatal("empty batch still stored")
	}
	if m, _ := filepath.Glob(filepath.Join(e.paths.Outbox, "*.manifest.json")); len(m) != 0 {
		t.Fatalf("manifest written for an empty batch: %v", m)
	}
}
