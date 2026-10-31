//go:build integration

// Integration test against a real clamd started from the shipped
// deploy/clamd/clamd.conf (see the clamd job in .github/workflows/ci.yml).
//
//	CLAMD_ADDR           clamd TCP address, e.g. 127.0.0.1:3310
//	CLAMD_TEST_HOST_DIR  folder on this machine that clamd has mounted
//	CLAMD_TEST_SEEN_AS   the same folder as clamd sees it, e.g. /data
package clamd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealClamd(t *testing.T) {
	addr, hostDir, seenAs := os.Getenv("CLAMD_ADDR"), os.Getenv("CLAMD_TEST_HOST_DIR"), os.Getenv("CLAMD_TEST_SEEN_AS")
	if addr == "" || hostDir == "" || seenAs == "" {
		t.Skip("CLAMD_ADDR, CLAMD_TEST_HOST_DIR and CLAMD_TEST_SEEN_AS must be set")
	}
	c := New(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("PING: %v", err)
	}
	v, err := c.Version(ctx)
	if err != nil || v.DBVersion == 0 {
		t.Fatalf("VERSION: %+v %v", v, err)
	}
	t.Logf("clamd: %s", v.Raw)

	write := func(name string, data []byte) string {
		p := filepath.Join(hostDir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(seenAs, name)
	}
	scan := func(path string) Result {
		r, err := c.Scan(ctx, path)
		if err != nil {
			t.Fatalf("SCAN %s: %v", path, err)
		}
		t.Logf("%s -> %+v", path, r)
		return r
	}

	if r := scan(write("clean.txt", []byte("hello, diode\n"))); r.Verdict != VerdictOK {
		t.Errorf("clean file: %+v", r)
	}
	if r := scan(write("eicar.txt", EICAR())); r.Verdict != VerdictFound {
		t.Errorf("EICAR not detected: %+v", r)
	}

	// A sparse file just over the 4000M limit must be reported as exceeding
	// it (AlertExceedsMax), never as OK.
	big := filepath.Join(hostDir, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4000<<20 + 1<<20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.Chmod(big, 0o644)
	r := scan(filepath.Join(seenAs, "big.bin"))
	if r.Verdict != VerdictFound || !strings.HasPrefix(r.Signature, "Heuristics.Limits.Exceeded.") {
		t.Errorf("oversized file not flagged: %+v", r)
	}
}
