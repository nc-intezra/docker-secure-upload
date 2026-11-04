// Package control serves the operator commands (list, release and delete
// held files) on a unix socket inside the app container, and is the client
// those commands use.
//
// Operators run them with `docker compose exec app diode-upload ...`. The
// socket is mode 0600 and only accepts connections from the service's own
// user id, so reaching it already requires Docker access on the host. It is
// never exposed on the network.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

// Ops is what the server needs from the pipeline.
type Ops interface {
	Withheld() []store.Upload
	Release(id, by, reason string) (store.Upload, error)
	Discard(id, by, reason string) (store.Upload, error)
}

// Item is one withheld file as the commands show it.
type Item struct {
	ID           string    `json:"id"`
	State        string    `json:"state"`
	Reason       string    `json:"reason"`
	Signature    string    `json:"signature,omitempty"`
	Username     string    `json:"username"`
	ClientIP     string    `json:"client_ip"`
	BatchID      string    `json:"batch_id"`
	OriginalName string    `json:"original_name"`
	OutboxName   string    `json:"outbox_name"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	ReceivedAt   time.Time `json:"received_at"`
}

func item(u store.Upload) Item {
	return Item{
		ID: u.ID, State: string(u.State), Reason: u.ScanReason, Signature: u.Signature,
		Username: u.Username, ClientIP: u.ClientIP, BatchID: u.BatchID,
		OriginalName: u.OriginalName, OutboxName: u.OutboxName, Size: u.Size,
		SHA256: u.SHA256, ReceivedAt: u.CompletedAt,
	}
}

// Request is the body of release and delete.
type Request struct {
	ID     string `json:"id"`
	By     string `json:"by"`
	Reason string `json:"reason"`
}

// Serve listens on path until ctx ends.
func Serve(ctx context.Context, path string, ops Ops, log *slog.Logger) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /held", func(w http.ResponseWriter, _ *http.Request) {
		items := []Item{}
		for _, u := range ops.Withheld() {
			items = append(items, item(u))
		}
		reply(w, http.StatusOK, items)
	})
	act := func(fn func(id, by, reason string) (store.Upload, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var req Request
			if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
				return
			}
			u, err := fn(req.ID, req.By, req.Reason)
			if err != nil {
				code := http.StatusConflict
				if errors.Is(err, store.ErrNotFound) {
					code = http.StatusNotFound
				}
				reply(w, code, map[string]string{"error": err.Error()})
				return
			}
			reply(w, http.StatusOK, item(u))
		}
	}
	mux.HandleFunc("POST /release", act(ops.Release))
	mux.HandleFunc("POST /delete", act(ops.Discard))

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Info("control socket ready", "path", path)
	err = srv.Serve(sameUser{ln.(*net.UnixListener), log})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// sameUser drops connections from any user id but our own.
type sameUser struct {
	*net.UnixListener
	log *slog.Logger
}

func (l sameUser) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err == nil && uid == os.Getuid() {
			return c, nil
		}
		l.log.Warn("control socket: connection from another user refused", "uid", uid, "err", err)
		c.Close()
	}
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}

// Client talks to Serve.
type Client struct{ http http.Client }

// NewClient returns a client for the socket at path.
func NewClient(path string) *Client {
	return &Client{http: http.Client{
		Timeout: 2 * time.Hour, // a release re-hashes the file first
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}},
	}}
}

func (c *Client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://control"+path, rd)
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the service's control socket (is the app running?): %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(res.Body).Decode(&e)
		return errors.New(e.Error)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// Held lists withheld files.
func (c *Client) Held() ([]Item, error) {
	var out []Item
	return out, c.do(http.MethodGet, "/held", nil, &out)
}

// Release releases a held file.
func (c *Client) Release(r Request) (Item, error) {
	var out Item
	return out, c.do(http.MethodPost, "/release", r, &out)
}

// Delete deletes a held or quarantined file.
func (c *Client) Delete(r Request) (Item, error) {
	var out Item
	return out, c.do(http.MethodPost, "/delete", r, &out)
}
