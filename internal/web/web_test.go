package web

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// A rejected request logs what the browser sent next to what was expected,
// so a wrong PUBLIC_ORIGIN can be spotted in `docker compose logs app`.
func TestRejectionIsLogged(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{
		PublicOrigin:  "https://upload.example.internal",
		CSRFKey:       bytes.Repeat([]byte("k"), 32),
		Uploads:       http.NotFoundHandler(),
		Instructions:  RenderInstructions(DefaultInstructions),
		MaxFileSize:   1 << 20,
		ChunkSize:     1 << 20,
		MaxBatchFiles: 10,
		Log:           slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(h)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Transport: srv.Client().Transport, Jar: jar}

	res, err := c.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	token := regexp.MustCompile(`csrf-token" content="([0-9a-f]+)"`).FindSubmatch(page)[1]

	sent := "https://10.1.2.3"
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/batches", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", string(token))
	req.Header.Set("Origin", sent)
	res, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", res.StatusCode)
	}

	var entry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) == nil && e["msg"] == "request rejected" {
			entry = e
		}
	}
	if entry == nil {
		t.Fatalf("no rejection logged:\n%s", logs.String())
	}
	if entry["reason"] != "bad_origin" || entry["origin"] != sent || entry["expected_origin"] != s.PublicOrigin || entry["has_csrf_token"] != true {
		t.Fatalf("log entry: %v", entry)
	}
}
