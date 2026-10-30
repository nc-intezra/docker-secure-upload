// Package config loads runtime settings from environment variables.
//
// Every setting has a safe default except the ones that describe the
// deployment (public origin, CSRF key). Secrets are read from files so they
// never appear in `docker inspect` output.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// OversizePolicy decides what happens to files clamd could not fully scan
// because of its size limits.
type OversizePolicy string

const (
	OversizePass   OversizePolicy = "pass"   // pass to the outbox, flagged unscanned
	OversizeHold   OversizePolicy = "hold"   // hold for admin review
	OversizeReject OversizePolicy = "reject" // refuse at upload creation
)

// Config holds every runtime setting.
type Config struct {
	PublicOrigin      string // e.g. https://upload.example
	ListenAddr        string // user site listener (behind the proxy)
	TrustedProxies    []netip.Prefix
	DataDir           string // incoming/, quarantine/, tmp/
	OutboxDir         string // the folder the diode watches
	StateDir          string // JSON store and audit log
	InstructionsFile  string
	CSRFKey           []byte
	MaxFileSize       int64
	ChunkSize         int64
	DiskReserve       int64
	UploadExpiry      time.Duration
	ClamdAddr         string
	ClamdPathPrefix   string // DataDir as seen by clamd (defaults to DataDir)
	ClamdMaxScanSize  int64  // must match clamd.conf MaxScanSize
	ScanConcurrency   int
	ScanTimeout       time.Duration
	OversizePolicy    OversizePolicy
	QuarantineEnabled bool
	MaxBatchFiles     int
}

// Load reads the configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		PublicOrigin:      os.Getenv("PUBLIC_ORIGIN"),
		ListenAddr:        env("LISTEN_ADDR", ":8080"),
		DataDir:           env("DATA_DIR", "/data"),
		StateDir:          env("STATE_DIR", "/state"),
		InstructionsFile:  env("INSTRUCTIONS_FILE", "/config/instructions.md"),
		ClamdAddr:         env("CLAMD_ADDR", "clamd:3310"),
		OversizePolicy:    OversizePolicy(env("OVERSIZE_POLICY", string(OversizePass))),
		QuarantineEnabled: true,
	}
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	c.OutboxDir = env("OUTBOX_DIR", filepath.Join(c.DataDir, "outbox"))
	c.ClamdPathPrefix = env("CLAMD_PATH_PREFIX", c.DataDir)

	var err error
	c.MaxFileSize, err = sizeEnv("MAX_FILE_SIZE", 50<<30)
	add(err)
	c.ChunkSize, err = sizeEnv("CHUNK_SIZE", 64<<20)
	add(err)
	c.DiskReserve, err = sizeEnv("DISK_RESERVE", 10<<30)
	add(err)
	c.ClamdMaxScanSize, err = sizeEnv("CLAMD_MAX_SCAN_SIZE", 4000<<20)
	add(err)
	c.UploadExpiry, err = durEnv("UPLOAD_EXPIRY", 24*time.Hour)
	add(err)
	c.ScanTimeout, err = durEnv("SCAN_TIMEOUT", 2*time.Hour)
	add(err)
	c.ScanConcurrency, err = intEnv("SCAN_CONCURRENCY", 2)
	add(err)
	c.MaxBatchFiles, err = intEnv("MAX_BATCH_FILES", 500)
	add(err)
	if v := os.Getenv("QUARANTINE_ENABLED"); v != "" {
		c.QuarantineEnabled, err = strconv.ParseBool(v)
		add(fieldErr("QUARANTINE_ENABLED", err))
	}

	proxies := env("TRUSTED_PROXY_CIDRS", "")
	for _, p := range strings.Split(proxies, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pfx, perr := netip.ParsePrefix(p)
		if perr != nil {
			add(fmt.Errorf("TRUSTED_PROXY_CIDRS: %w", perr))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, pfx)
	}

	keyFile := env("CSRF_KEY_FILE", "/run/secrets/csrf_key")
	c.CSRFKey, err = os.ReadFile(keyFile)
	if err != nil {
		add(fmt.Errorf("CSRF key: %w", err))
	} else {
		c.CSRFKey = []byte(strings.TrimSpace(string(c.CSRFKey)))
		if len(c.CSRFKey) < 32 {
			add(errors.New("CSRF key must be at least 32 bytes"))
		}
	}

	add(c.validate())
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func (c *Config) validate() error {
	var errs []error
	u, err := url.Parse(c.PublicOrigin)
	if c.PublicOrigin == "" || err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
		errs = append(errs, errors.New("PUBLIC_ORIGIN must be an origin such as https://upload.example"))
	}
	switch c.OversizePolicy {
	case OversizePass, OversizeHold, OversizeReject:
	default:
		errs = append(errs, fmt.Errorf("OVERSIZE_POLICY must be pass, hold or reject, not %q", c.OversizePolicy))
	}
	if c.ChunkSize < 1<<20 || c.ChunkSize > 1<<30 {
		errs = append(errs, errors.New("CHUNK_SIZE must be between 1 MiB and 1 GiB"))
	}
	if c.MaxFileSize <= 0 {
		errs = append(errs, errors.New("MAX_FILE_SIZE must be positive"))
	}
	if c.ScanConcurrency < 1 || c.ScanConcurrency > 64 {
		errs = append(errs, errors.New("SCAN_CONCURRENCY must be between 1 and 64"))
	}
	if c.MaxBatchFiles < 1 {
		errs = append(errs, errors.New("MAX_BATCH_FILES must be positive"))
	}
	for name, dir := range map[string]string{"DATA_DIR": c.DataDir, "OUTBOX_DIR": c.OutboxDir, "STATE_DIR": c.StateDir} {
		if !filepath.IsAbs(dir) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path", name))
		}
	}
	return errors.Join(errs...)
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func fieldErr(key string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", key, err)
}

func intEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	return n, fieldErr(key, err)
}

func durEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := ParseDuration(v)
	return d, fieldErr(key, err)
}

// ParseDuration accepts Go durations plus a "d" suffix for days.
func ParseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func sizeEnv(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := ParseSize(v)
	return n, fieldErr(key, err)
}

// ParseSize parses sizes such as "64MiB", "50GiB", "4000M" or "1048576".
// Both SI-looking and binary suffixes are treated as binary, matching clamd.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
		{"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10},
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s = strings.TrimSuffix(s, u.suffix)
			mult = u.mult
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("size %q too large", s)
	}
	return n * mult, nil
}
