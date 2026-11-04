// Package e2e drives the whole user flow over HTTP against a fake clamd:
// page load, batch creation, resumable tus upload, scan, outbox handoff.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/audit"
	"github.com/nc-intezra/docker-secure-upload/internal/clamd"
	"github.com/nc-intezra/docker-secure-upload/internal/config"
	"github.com/nc-intezra/docker-secure-upload/internal/pipeline"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
	"github.com/nc-intezra/docker-secure-upload/internal/tus"
	"github.com/nc-intezra/docker-secure-upload/internal/web"
)

const maxScan = 4096 // the fake scanner's "MaxScanSize"

// fakeClamd answers PING, VERSION and SCAN like clamd does.
func fakeClamd(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				cmd, _ := bufio.NewReader(c).ReadString(0)
				cmd = strings.TrimSuffix(cmd, "\x00")
				switch {
				case cmd == "zPING":
					io.WriteString(c, "PONG\x00")
				case cmd == "zVERSION":
					io.WriteString(c, "ClamAV 1.4.1/27800/Thu Oct 29 08:24:02 2026\x00")
				case strings.HasPrefix(cmd, "zSCAN "):
					p := strings.TrimPrefix(cmd, "zSCAN ")
					b, err := os.ReadFile(p)
					switch {
					case err != nil:
						fmt.Fprintf(c, "%s: lstat() failed. ERROR\x00", p)
					case bytes.Contains(b, clamd.EICAR()):
						fmt.Fprintf(c, "%s: Eicar-Signature FOUND\x00", p)
					case bytes.Contains(b, []byte("NESTED-BOMB")):
						fmt.Fprintf(c, "%s: Heuristics.Limits.Exceeded.MaxRecursion FOUND\x00", p)
					default:
						// Like real clamd with default settings, files over
						// the limit come back OK without being read.
						fmt.Fprintf(c, "%s: OK\x00", p)
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

type env struct {
	t      *testing.T
	srv    *httptest.Server
	paths  pipeline.Paths
	state  string
	pipe   *pipeline.Pipeline
	cancel context.CancelFunc
}

// option adjusts the service before it starts.
type option func(*pipeline.Pipeline, *tus.Handler, *web.Server)

func newEnv(t *testing.T, quarantine bool, opts ...option) *env {
	t.Helper()
	root := t.TempDir()
	paths := pipeline.NewPaths(filepath.Join(root, "data"), filepath.Join(root, "data", "outbox"))
	os.MkdirAll(paths.Outbox, 0o755)
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(stateDir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pipe := &pipeline.Pipeline{
		Store: st, Audit: al, Scanner: clamd.New(fakeClamd(t)), Paths: paths,
		Policy:      pipeline.Policy{MaxScanSize: maxScan, Oversize: config.OversizePass, QuarantineEnabled: quarantine},
		ClamdPrefix: paths.DataDir, ScanTimeout: 10 * time.Second, Concurrency: 2,
		UploadExpiry: time.Hour, Log: log,
	}
	up := &tus.Handler{
		BasePath: "/api/v1/uploads/", IncomingDir: paths.Incoming, Store: st, Audit: al,
		Pipeline: pipe, MaxFileSize: 1 << 20, ChunkSize: 1024, Log: log,
	}
	site := &web.Server{
		TrustedProxies: nil, CSRFKey: bytes.Repeat([]byte("k"), 32), Store: st, Audit: al,
		Uploads: up, Instructions: web.RenderInstructions(web.DefaultInstructions),
		MaxFileSize: 1 << 20, ChunkSize: 1024, MaxBatchFiles: 10, Log: log,
	}
	for _, o := range opts {
		o(pipe, up, site)
	}
	pipe.Init()
	ctx, cancel := context.WithCancel(context.Background())
	pipe.Start(ctx)
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS() // __Host- cookies need a secure origin
	site.PublicOrigin = srv.URL
	h, err := site.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	e := &env{t: t, srv: srv, paths: paths, state: stateDir, pipe: pipe, cancel: cancel}
	t.Cleanup(func() { cancel(); srv.Close() })
	return e
}

type client struct {
	e    *env
	http *http.Client
	csrf string
}

var csrfMeta = regexp.MustCompile(`<meta name="csrf-token" content="([0-9a-f]+)">`)

func (e *env) newClient() *client {
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Transport: e.srv.Client().Transport, Jar: jar}
	res, err := hc.Get(e.srv.URL + "/")
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := csrfMeta.FindSubmatch(body)
	if m == nil {
		e.t.Fatalf("no CSRF token in page")
	}
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security", "Referrer-Policy"} {
		if res.Header.Get(h) == "" {
			e.t.Errorf("missing header %s", h)
		}
	}
	return &client{e: e, http: hc, csrf: string(m[1])}
}

func (c *client) do(method, path string, body io.Reader, hdr map[string]string) *http.Response {
	req, _ := http.NewRequest(method, c.e.srv.URL+path, body)
	req.Header.Set("Origin", c.e.srv.URL)
	req.Header.Set("X-CSRF-Token", c.csrf)
	req.Header.Set("Tus-Resumable", "1.0.0")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	return res
}

func (c *client) batch(user string, n int) string { return c.batchOpts(user, n, false) }

func (c *client) batchOpts(user string, n int, prefix bool) string {
	res := c.do("POST", "/api/v1/batches", strings.NewReader(fmt.Sprintf(`{"username":%q,"file_count":%d,"prefix_names":%t}`, user, n, prefix)),
		map[string]string{"Content-Type": "application/json"})
	defer res.Body.Close()
	if res.StatusCode != 201 {
		b, _ := io.ReadAll(res.Body)
		c.e.t.Fatalf("create batch: %d %s", res.StatusCode, b)
	}
	var v struct {
		BatchID string `json:"batch_id"`
	}
	json.NewDecoder(res.Body).Decode(&v)
	return v.BatchID
}

func meta(batch, name string) string {
	return "batch_id " + base64.StdEncoding.EncodeToString([]byte(batch)) + ",filename " + base64.StdEncoding.EncodeToString([]byte(name))
}

func (c *client) create(batch, name string, size int) (string, int) {
	res := c.do("POST", "/api/v1/uploads/", nil, map[string]string{
		"Upload-Length": strconv.Itoa(size), "Upload-Metadata": meta(batch, name),
	})
	res.Body.Close()
	return res.Header.Get("Location"), res.StatusCode
}

func (c *client) patch(loc string, off int, data []byte) *http.Response {
	return c.do("PATCH", loc, bytes.NewReader(data), map[string]string{
		"Content-Type": "application/offset+octet-stream", "Upload-Offset": strconv.Itoa(off),
	})
}

// upload resumes from the server's offset and sends the rest of data in
// chunks of at most 1000 bytes.
func (c *client) upload(loc string, data []byte) {
	res := c.do("HEAD", loc, nil, nil)
	res.Body.Close()
	off, _ := strconv.Atoi(res.Header.Get("Upload-Offset"))
	for off < len(data) {
		end := min(off+1000, len(data))
		res := c.patch(loc, off, data[off:end])
		res.Body.Close()
		if res.StatusCode != 204 {
			c.e.t.Fatalf("PATCH at %d: %d", off, res.StatusCode)
		}
		off, _ = strconv.Atoi(res.Header.Get("Upload-Offset"))
	}
}

type status struct {
	Closed bool `json:"closed"`
	Files  []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		State  string `json:"state"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

func (c *client) waitClosed(batch string) status {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		res := c.do("GET", "/api/v1/batches/"+batch, nil, nil)
		var s status
		json.NewDecoder(res.Body).Decode(&s)
		res.Body.Close()
		if s.Closed {
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.e.t.Fatalf("batch %s did not close", batch)
	return status{}
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestEndToEnd(t *testing.T) {
	e := newEnv(t, true)
	c := e.newClient()

	clean := bytes.Repeat([]byte("clean data "), 300) // 3300 bytes, 4 chunks
	infected := append([]byte("prefix "), clamd.EICAR()...)
	big := bytes.Repeat([]byte("B"), maxScan+10) // over the scan limit
	bomb := []byte("NESTED-BOMB")
	empty := []byte{}

	b := c.batchOpts("JSmith", 5, true) // opted in to batch-prefixed names
	type item struct {
		name string
		data []byte
		want string
	}
	items := []item{
		{"Site Survey.zip", clean, "sent"},
		{"eicar.com", infected, "blocked"},
		{"vm-image.qcow2", big, "sent_unscanned"},
		{"bomb.zip", bomb, "held"},
		{"empty.txt", empty, "sent"},
	}
	for i, it := range items {
		loc, code := c.create(b, it.name, len(it.data))
		if code != 201 {
			t.Fatalf("create %s: %d", it.name, code)
		}
		if i == 0 {
			// Interrupted chunk: send half of the first chunk and stop. tus
			// commits what arrived; resume from HEAD.
			res := c.patch(loc, 0, it.data[:500])
			res.Body.Close()
			res = c.do("HEAD", loc, nil, nil)
			res.Body.Close()
			if res.Header.Get("Upload-Offset") != "500" {
				t.Fatalf("HEAD offset = %s", res.Header.Get("Upload-Offset"))
			}
			// A stale offset is refused.
			res = c.patch(loc, 0, it.data[:10])
			res.Body.Close()
			if res.StatusCode != 409 {
				t.Fatalf("stale offset accepted: %d", res.StatusCode)
			}
			c.upload(loc, it.data) // upload() restarts from the server offset
			continue
		}
		c.upload(loc, it.data)
	}

	s := c.waitClosed(b)
	if len(s.Files) != len(items) {
		t.Fatalf("got %d files", len(s.Files))
	}
	for i, f := range s.Files {
		if f.State != items[i].want {
			t.Errorf("%s: state %s, want %s", items[i].name, f.State, items[i].want)
		}
		if f.SHA256 != sha(items[i].data) {
			t.Errorf("%s: sha256 %s", items[i].name, f.SHA256)
		}
	}

	// Outbox: two passed files, one unscanned, their sidecars and the manifest.
	ents, _ := os.ReadDir(e.paths.Outbox)
	var got []string
	for _, x := range ents {
		got = append(got, x.Name())
	}
	want := []string{
		b + "_001_Site Survey.zip", b + "_001_Site Survey.zip.sha256",
		b + "_003_vm-image.qcow2", b + "_003_vm-image.qcow2.sha256",
		b + "_005_empty.txt", b + "_005_empty.txt.sha256",
		b + ".manifest.json",
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("outbox:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.HasPrefix(b, time.Now().UTC().Format("20060102")) || !strings.Contains(b, "-jsmith-") {
		t.Errorf("batch id %s", b)
	}
	data, _ := os.ReadFile(filepath.Join(e.paths.Outbox, b+"_001_Site Survey.zip"))
	if !bytes.Equal(data, clean) {
		t.Fatal("outbox file differs from upload")
	}
	side, _ := os.ReadFile(filepath.Join(e.paths.Outbox, b+"_001_Site Survey.zip.sha256"))
	if string(side) != sha(clean)+"  "+b+"_001_Site Survey.zip\n" {
		t.Fatalf("sidecar %q", side)
	}

	raw, _ := os.ReadFile(filepath.Join(e.paths.Outbox, b+".manifest.json"))
	var man map[string]any
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	files := man["files"].([]any)
	if len(files) != 3 || man["withheld_count"].(float64) != 2 || man["username"] != "jsmith" {
		t.Fatalf("manifest: %s", raw)
	}
	if files[1].(map[string]any)["scan_status"] != "unscanned" || files[0].(map[string]any)["original_name"] != "Site Survey.zip" {
		t.Fatalf("manifest files: %s", raw)
	}
	if strings.Contains(string(raw), "Eicar") || strings.Contains(string(raw), "eicar.com") {
		t.Fatal("withheld file details leaked into the manifest")
	}

	// Infected and held files are in quarantine, not in staging.
	q, _ := os.ReadDir(e.paths.Quarantine)
	in, _ := os.ReadDir(e.paths.Incoming)
	if len(q) != 2 || len(in) != 0 {
		t.Fatalf("quarantine %d, incoming %d", len(q), len(in))
	}
	if n, err := audit.Verify(filepath.Join(e.state, "audit")); err != nil || n < 10 {
		t.Fatalf("audit verify: %d %v", n, err)
	}
}

func TestQuarantineOffDeletes(t *testing.T) {
	e := newEnv(t, false)
	c := e.newClient()
	b := c.batch("alice", 1)
	data := clamd.EICAR()
	loc, _ := c.create(b, "x.com", len(data))
	c.upload(loc, data)
	s := c.waitClosed(b)
	if s.Files[0].State != "blocked" {
		t.Fatal(s.Files[0].State)
	}
	q, _ := os.ReadDir(e.paths.Quarantine)
	in, _ := os.ReadDir(e.paths.Incoming)
	if len(q) != 0 || len(in) != 0 {
		t.Fatalf("file kept: quarantine %d incoming %d", len(q), len(in))
	}
}

func TestRequestChecks(t *testing.T) {
	e := newEnv(t, true)
	c := e.newClient()
	b := c.batch("bob", 1)

	// CSRF token missing, wrong origin, cross-site fetch.
	for name, hdr := range map[string]map[string]string{
		"no token":   {"X-CSRF-Token": ""},
		"bad token":  {"X-CSRF-Token": strings.Repeat("0", 64)},
		"no origin":  {"Origin": ""},
		"evil":       {"Origin": "https://evil.example"},
		"cross-site": {"Sec-Fetch-Site": "cross-site"},
	} {
		hdr["Upload-Length"] = "10"
		hdr["Upload-Metadata"] = meta(b, "a.txt")
		res := c.do("POST", "/api/v1/uploads/", nil, hdr)
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Errorf("%s: got %d, want 403", name, res.StatusCode)
		}
	}

	loc, code := c.create(b, "a.txt", 10)
	if code != 201 {
		t.Fatal(code)
	}
	// Another session cannot see or write the upload or the batch.
	other := e.newClient()
	if res := other.do("HEAD", loc, nil, nil); res.StatusCode != 404 {
		t.Errorf("foreign HEAD: %d", res.StatusCode)
	}
	if res := other.patch(loc, 0, []byte("0123456789")); res.StatusCode != 404 {
		t.Errorf("foreign PATCH: %d", res.StatusCode)
	}
	if res := other.do("GET", "/api/v1/batches/"+b, nil, nil); res.StatusCode != 404 {
		t.Errorf("foreign batch read: %d", res.StatusCode)
	}
	if _, code := other.create(b, "b.txt", 1); code != 404 {
		t.Errorf("foreign batch upload: %d", code)
	}

	// Batch declared one file; a second is refused.
	if _, code := c.create(b, "b.txt", 1); code != 409 {
		t.Errorf("over-full batch: %d", code)
	}
	// Bad requests.
	b2 := c.batch("bob", 5)
	cases := map[string]map[string]string{
		"unknown metadata": {"Upload-Length": "1", "Upload-Metadata": meta(b2, "a") + ",evil eA=="},
		"no length":        {"Upload-Metadata": meta(b2, "a")},
		"deferred length":  {"Upload-Defer-Length": "1", "Upload-Metadata": meta(b2, "a")},
		"newline in name":  {"Upload-Length": "1", "Upload-Metadata": meta(b2, "a\nb")},
		"bad batch":        {"Upload-Length": "1", "Upload-Metadata": meta("../../etc", "a")},
	}
	for name, hdr := range cases {
		res := c.do("POST", "/api/v1/uploads/", nil, hdr)
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Errorf("%s: got %d, want 400", name, res.StatusCode)
		}
	}
	res := c.do("POST", "/api/v1/uploads/", nil, map[string]string{"Upload-Length": strconv.Itoa(2 << 20), "Upload-Metadata": meta(b2, "a")})
	if res.StatusCode != 413 {
		t.Errorf("too large: %d", res.StatusCode)
	}
	// Oversized chunk and wrong content type.
	loc2, _ := c.create(b2, "c.txt", 5000)
	if res := c.patch(loc2, 0, make([]byte, 2000)); res.StatusCode != 413 {
		t.Errorf("chunk over limit: %d", res.StatusCode)
	}
	if res := c.do("PATCH", loc2, strings.NewReader("x"), map[string]string{"Upload-Offset": "0", "Content-Type": "text/plain"}); res.StatusCode != 415 {
		t.Errorf("content type: %d", res.StatusCode)
	}
	// Bad usernames and JSON.
	for _, body := range []string{`{"username":"1bad","file_count":1}`, `{"username":"ok","file_count":0}`, `{"username":"ok","file_count":1,"x":1}`, `not json`} {
		res := c.do("POST", "/api/v1/batches", strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Errorf("batch %s: %d", body, res.StatusCode)
		}
	}
	// Cancel releases the upload.
	if res := c.do("DELETE", loc2, nil, nil); res.StatusCode != 204 {
		t.Errorf("DELETE: %d", res.StatusCode)
	}
	if res := c.patch(loc2, 0, []byte("x")); res.StatusCode != 409 {
		t.Errorf("PATCH after cancel: %d", res.StatusCode)
	}
}

func TestCrashRecoveryPlacesFile(t *testing.T) {
	// A decision recorded before the process died is completed by the
	// janitor: the file still in incoming/ is moved to the outbox.
	e := newEnv(t, true)
	c := e.newClient()
	b := c.batch("carol", 1)
	data := []byte("hello")
	loc, _ := c.create(b, "h.txt", len(data))
	c.upload(loc, data)
	c.waitClosed(b)
	id := loc[strings.LastIndex(loc, "/")+1:]

	// Simulate: rewind to "decided but not placed".
	e.cancel() // stop workers; drive the janitor by hand
	st := e.pipe.Store
	u, _ := st.Upload(id)
	name := filepath.Join(e.paths.Outbox, u.OutboxName)
	os.Rename(name, filepath.Join(e.paths.Incoming, id))
	os.Remove(name + ".sha256")
	st.UpdateUpload(id, func(x *store.Upload) error { x.Placed = false; x.SidecarDone = false; return nil })

	e.pipe.Janitor()
	if _, err := os.Stat(name); err != nil {
		t.Fatal("file not re-placed")
	}
	if _, err := os.Stat(name + ".sha256"); err != nil {
		t.Fatal("sidecar not re-written")
	}
}

// By default files keep their own names. A second file with the same name
// waits until the diode has collected the first one; it never overwrites it.
func TestPlainNamesWaitForSameName(t *testing.T) {
	e := newEnv(t, true)
	c := e.newClient()
	first, second := []byte("first version"), []byte("second version")

	a := c.batch("alice", 1)
	loc, _ := c.create(a, "Quarterly Report (final).pdf", len(first))
	c.upload(loc, first)
	c.waitClosed(a)

	name := filepath.Join(e.paths.Outbox, "Quarterly Report (final).pdf")
	if got, _ := os.ReadFile(name); !bytes.Equal(got, first) {
		t.Fatalf("first file not in outbox under its own name: %q", got)
	}
	side, _ := os.ReadFile(name + ".sha256")
	if string(side) != sha(first)+"  Quarterly Report (final).pdf\n" {
		t.Fatalf("sidecar %q", side)
	}

	b := c.batch("bob", 1)
	loc, _ = c.create(b, "Quarterly Report (final).pdf", len(second))
	c.upload(loc, second)
	// Scanned and passed, but waiting: the first file is still there.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res := c.do("GET", "/api/v1/batches/"+b, nil, nil)
		var s status
		json.NewDecoder(res.Body).Decode(&s)
		res.Body.Close()
		if s.Files[0].State == "sent" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.pipe.Janitor()
	if got, _ := os.ReadFile(name); !bytes.Equal(got, first) {
		t.Fatal("first file was overwritten")
	}

	// The diode collects the data file; its sidecar is still there, so the
	// second file keeps waiting.
	os.Remove(name)
	e.pipe.Janitor()
	if _, err := os.Stat(name); err == nil {
		t.Fatal("second file placed while the first file's sidecar was still in the outbox")
	}

	// The sidecar goes too; now the second file moves in.
	os.Remove(name + ".sha256")
	e.pipe.Janitor()
	c.waitClosed(b)
	if got, _ := os.ReadFile(name); !bytes.Equal(got, second) {
		t.Fatalf("second file not placed: %q", got)
	}
	side, _ = os.ReadFile(name + ".sha256")
	if string(side) != sha(second)+"  Quarterly Report (final).pdf\n" {
		t.Fatalf("second sidecar %q", side)
	}
	raw, _ := os.ReadFile(filepath.Join(e.paths.Outbox, b+".manifest.json"))
	if !strings.Contains(string(raw), `"name": "Quarterly Report (final).pdf"`) {
		t.Fatalf("manifest: %s", raw)
	}
}
