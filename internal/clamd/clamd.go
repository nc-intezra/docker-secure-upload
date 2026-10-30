// Package clamd is a minimal client for the clamd TCP protocol, using the
// NUL-terminated "z" command forms. Files are scanned by path (zSCAN), so
// clamd reads them from its own read-only mount and its stream size limit
// does not apply.
package clamd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Verdict classes reported by Scan.
const (
	VerdictOK    = "OK"
	VerdictFound = "FOUND"
	VerdictError = "ERROR"
)

// Result is one scan's outcome. Signature is set for FOUND, Message for ERROR.
type Result struct {
	Verdict   string
	Signature string
	Message   string
}

// Client talks to one clamd.
type Client struct {
	Addr        string
	DialTimeout time.Duration
}

// New returns a client for addr (host:port).
func New(addr string) *Client { return &Client{Addr: addr, DialTimeout: 5 * time.Second} }

func (c *Client) roundTrip(ctx context.Context, cmd string) (string, error) {
	d := net.Dialer{Timeout: c.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	// Close the connection if the context is cancelled mid-scan.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := io.WriteString(conn, "z"+cmd+"\x00"); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(io.LimitReader(conn, 64<<10)).ReadString(0)
	if err != nil && !(errors.Is(err, io.EOF) && reply != "") {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	return strings.TrimRight(reply, "\x00\n"), nil
}

// Ping returns nil if clamd answers PONG.
func (c *Client) Ping(ctx context.Context) error {
	r, err := c.roundTrip(ctx, "PING")
	if err != nil {
		return err
	}
	if r != "PONG" {
		return fmt.Errorf("unexpected PING reply %q", r)
	}
	return nil
}

// Version describes the engine and signature database.
type Version struct {
	Raw       string    // e.g. "ClamAV 1.4.1/27800/Thu Oct 29 08:24:02 2026"
	Engine    string    // "ClamAV 1.4.1"
	DBVersion int       // 27800
	DBTime    time.Time // signature build time, zero if unknown
}

// Version asks clamd for its engine and database versions.
func (c *Client) Version(ctx context.Context) (Version, error) {
	r, err := c.roundTrip(ctx, "VERSION")
	if err != nil {
		return Version{}, err
	}
	return ParseVersion(r), nil
}

// ParseVersion parses a VERSION reply. Unknown parts are left zero.
func ParseVersion(r string) Version {
	v := Version{Raw: r}
	parts := strings.SplitN(r, "/", 3)
	v.Engine = parts[0]
	if len(parts) > 1 {
		v.DBVersion, _ = strconv.Atoi(parts[1])
	}
	if len(parts) > 2 {
		if t, err := time.Parse("Mon Jan _2 15:04:05 2006", strings.TrimSpace(parts[2])); err == nil {
			v.DBTime = t
		}
	}
	return v
}

// Scan asks clamd to scan path (as clamd sees it). The path must not contain
// newlines or NUL; callers only pass server-generated names.
func (c *Client) Scan(ctx context.Context, path string) (Result, error) {
	if strings.ContainsAny(path, "\x00\n\r") {
		return Result{}, errors.New("invalid scan path")
	}
	r, err := c.roundTrip(ctx, "SCAN "+path)
	if err != nil {
		return Result{}, err
	}
	return ParseScanReply(path, r)
}

// ParseScanReply interprets "<path>: OK", "<path>: <sig> FOUND" and
// "<path>: <message> ERROR". Anything else is an error, never a pass.
func ParseScanReply(path, reply string) (Result, error) {
	prefix := path + ": "
	if !strings.HasPrefix(reply, prefix) {
		// clamd reports some errors without the path prefix.
		if strings.HasSuffix(reply, " ERROR") {
			return Result{Verdict: VerdictError, Message: strings.TrimSuffix(reply, " ERROR")}, nil
		}
		return Result{}, fmt.Errorf("unexpected scan reply %q", reply)
	}
	body := strings.TrimPrefix(reply, prefix)
	switch {
	case body == "OK":
		return Result{Verdict: VerdictOK}, nil
	case strings.HasSuffix(body, " FOUND"):
		sig := strings.TrimSuffix(body, " FOUND")
		if sig == "" {
			return Result{}, fmt.Errorf("FOUND without signature in %q", reply)
		}
		return Result{Verdict: VerdictFound, Signature: sig}, nil
	case strings.HasSuffix(body, " ERROR"):
		return Result{Verdict: VerdictError, Message: strings.TrimSuffix(body, " ERROR")}, nil
	}
	return Result{}, fmt.Errorf("unexpected scan reply %q", reply)
}

// EICAR returns the standard antivirus test string. It is assembled at run
// time so the binary itself does not trip scanners.
func EICAR() []byte {
	var b bytes.Buffer
	b.WriteString(`X5O!P%@AP[4\PZX54(P^)7CC)7}$`)
	b.WriteString("EICAR-STANDARD-ANTIVIRUS-")
	b.WriteString("TEST-FILE!$H+H*")
	return b.Bytes()
}
