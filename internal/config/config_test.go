package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	cases := map[string]int64{"1048576": 1 << 20, "64MiB": 64 << 20, "4000M": 4000 << 20, "50GiB": 50 << 30, "1T": 1 << 40}
	for in, want := range cases {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "abc", "1.5G", "99999999999T"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}

func TestParseDuration(t *testing.T) {
	if d, err := ParseDuration("7d"); err != nil || d != 7*24*time.Hour {
		t.Fatal(d, err)
	}
	if d, err := ParseDuration("90m"); err != nil || d != 90*time.Minute {
		t.Fatal(d, err)
	}
}

func TestLoad(t *testing.T) {
	key := filepath.Join(t.TempDir(), "csrf")
	os.WriteFile(key, []byte(strings.Repeat("x", 32)+"\n"), 0o600)
	t.Setenv("CSRF_KEY_FILE", key)
	t.Setenv("PUBLIC_ORIGIN", "https://upload.example")
	t.Setenv("TRUSTED_PROXY_CIDRS", "172.20.0.0/16, 10.0.0.1/32")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.OutboxDir != "/data/outbox" || c.ChunkSize != 64<<20 || len(c.TrustedProxies) != 2 || c.OversizePolicy != OversizeHold || !c.QuarantineEnabled ||
		c.UploadExpiry != time.Hour || c.SessionLimits.Reserved != 100<<30 || c.IPLimits.OpenUploads != 60 {
		t.Fatalf("%+v", c)
	}

	t.Setenv("PUBLIC_ORIGIN", "https://upload.example/path")
	t.Setenv("OVERSIZE_POLICY", "maybe")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PUBLIC_ORIGIN") || !strings.Contains(err.Error(), "OVERSIZE_POLICY") {
		t.Fatalf("expected both errors, got %v", err)
	}
}
