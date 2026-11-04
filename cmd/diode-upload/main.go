// Command diode-upload runs the upload service.
//
//	diode-upload               run the service
//	diode-upload healthcheck   exit 0 if the local /readyz answers 200 (for Docker)
//	diode-upload verify-audit  check the audit log hash chain
//	diode-upload version       print the version
//	diode-upload held          list held and quarantined files
//	diode-upload release ID --by NAME --reason TEXT
//	diode-upload delete ID --by NAME --reason TEXT
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/audit"
	"github.com/nc-intezra/docker-secure-upload/internal/clamd"
	"github.com/nc-intezra/docker-secure-upload/internal/config"
	"github.com/nc-intezra/docker-secure-upload/internal/control"
	"github.com/nc-intezra/docker-secure-upload/internal/fsutil"
	"github.com/nc-intezra/docker-secure-upload/internal/limits"
	"github.com/nc-intezra/docker-secure-upload/internal/pipeline"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
	"github.com/nc-intezra/docker-secure-upload/internal/tus"
	"github.com/nc-intezra/docker-secure-upload/internal/web"
)

// version is set at build time with -ldflags "-X main.version=v0.5.3-beta".
var version = "dev"

func main() {
	pipeline.Version = version
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "verify-audit":
			os.Exit(verifyAudit())
		case "version", "--version", "-v":
			fmt.Printf("diode-upload %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			os.Exit(0)
		case "held", "release", "delete":
			os.Exit(operator(os.Args[1], os.Args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func healthAddr() string {
	if v := os.Getenv("HEALTH_ADDR"); v != "" {
		return v
	}
	return "127.0.0.1:9100"
}

func healthcheck() int {
	addr := healthAddr()
	if host, port, ok := cutHostPort(addr); ok && (host == "" || host == "0.0.0.0") {
		addr = "127.0.0.1:" + port
	}
	c := http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://" + addr + "/readyz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func cutHostPort(a string) (string, string, bool) {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] == ':' {
			return a[:i], a[i+1:], true
		}
	}
	return "", "", false
}

func verifyAudit() int {
	dir := filepath.Join(envOr("STATE_DIR", "/state"), "audit")
	n, err := audit.Verify(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit chain FAILED after %d events: %v\n", n, err)
		return 1
	}
	fmt.Printf("audit chain OK: %d events\n", n)
	return 0
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func run(log *slog.Logger) error {
	log.Info("starting", "version", version, "go", runtime.Version())
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	paths := pipeline.NewPaths(cfg.DataDir, cfg.OutboxDir)
	if err := paths.Prepare(); err != nil {
		return fmt.Errorf("storage layout: %w", err)
	}
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("state store: %w", err)
	}
	auditLog, err := audit.Open(filepath.Join(cfg.StateDir, "audit"))
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}

	pipe := &pipeline.Pipeline{
		Store:   st,
		Audit:   auditLog,
		Scanner: clamd.New(cfg.ClamdAddr),
		Paths:   paths,
		Policy: pipeline.Policy{
			MaxScanSize:       cfg.ClamdMaxScanSize,
			Oversize:          cfg.OversizePolicy,
			QuarantineEnabled: cfg.QuarantineEnabled,
		},
		ClamdPrefix:  cfg.ClamdPathPrefix,
		ScanTimeout:  cfg.ScanTimeout,
		Concurrency:  cfg.ScanConcurrency,
		UploadExpiry: cfg.UploadExpiry,
		Log:          log,
	}
	pipe.Init()

	caps := &limits.Checker{Session: cfg.SessionLimits, IP: cfg.IPLimits, Store: st}
	var rejectAbove int64
	if cfg.OversizePolicy == config.OversizeReject {
		rejectAbove = cfg.ClamdMaxScanSize
	}
	uploads := &tus.Handler{
		BasePath:    "/api/v1/uploads/",
		IncomingDir: paths.Incoming,
		Store:       st,
		Audit:       auditLog,
		Pipeline:    pipe,
		MaxFileSize: cfg.MaxFileSize,
		ChunkSize:   cfg.ChunkSize,
		DiskReserve: cfg.DiskReserve,
		RejectAbove: rejectAbove,
		Limits:      caps,
		Log:         log,
	}
	site := &web.Server{
		PublicOrigin:   cfg.PublicOrigin,
		TrustedProxies: cfg.TrustedProxies,
		CSRFKey:        cfg.CSRFKey,
		Store:          st,
		Audit:          auditLog,
		Uploads:        uploads,
		Instructions:   web.LoadInstructions(cfg.InstructionsFile),
		MaxFileSize:    cfg.MaxFileSize,
		ChunkSize:      cfg.ChunkSize,
		MaxBatchFiles:  cfg.MaxBatchFiles,
		Limits:         caps,
		Log:            log,
	}
	handler, err := site.Handler()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pipe.Start(ctx)
	if cfg.ControlSocket != "" {
		go func() {
			if err := control.Serve(ctx, cfg.ControlSocket, pipe, log); err != nil {
				log.Error("control socket", "err", err)
			}
		}()
	}

	_ = auditLog.Append(audit.Event{ActorType: "system", Actor: "service", Action: "service.started",
		Details: map[string]string{"version": version, "oversize_policy": string(cfg.OversizePolicy), "quarantine_enabled": fmt.Sprint(cfg.QuarantineEnabled)}})

	userSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		// No ReadTimeout/WriteTimeout: a 64 MiB chunk on a slow link can take
		// minutes. The proxy enforces per-read body timeouts instead.
	}
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	healthMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !pipe.Healthy() {
			http.Error(w, "scanner not ready", http.StatusServiceUnavailable)
			return
		}
		if free, err := fsutil.FreeBytes(paths.Incoming); err != nil || free < cfg.DiskReserve {
			http.Error(w, "staging disk below reserve", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	healthSrv := &http.Server{Addr: envOr("HEALTH_ADDR", "0.0.0.0:9100"), Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() { errc <- userSrv.ListenAndServe() }()
	go func() { errc <- healthSrv.ListenAndServe() }()
	log.Info("listening", "site", cfg.ListenAddr, "health", healthSrv.Addr, "outbox", cfg.OutboxDir)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	log.Info("shutting down")
	shut, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = healthSrv.Shutdown(shut)
	return userSrv.Shutdown(shut)
}
