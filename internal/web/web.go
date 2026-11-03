// Package web serves the user upload site: the page, the batch API and the
// tus endpoint, behind session, CSRF, origin and header middleware.
package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/audit"
	"github.com/nc-intezra/docker-secure-upload/internal/names"
	"github.com/nc-intezra/docker-secure-upload/internal/reqctx"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

//go:embed static templates
var assets embed.FS

const (
	sessionCookie = "__Host-sid"
	uploadsPath   = "/api/v1/uploads/"
)

var (
	sidPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	assetPattern = regexp.MustCompile(`^[a-z0-9-]+\.(js|css)$`)
)

// Server is the user-facing site.
type Server struct {
	PublicOrigin   string
	TrustedProxies []netip.Prefix
	CSRFKey        []byte
	Store          *store.Store
	Audit          *audit.Log
	Uploads        http.Handler // tus handler mounted at /api/v1/uploads/
	Instructions   template.HTML
	MaxFileSize    int64
	ChunkSize      int64
	MaxBatchFiles  int
	Log            *slog.Logger

	page   *template.Template
	static fs.FS
}

// Handler builds the routed, wrapped handler.
func (s *Server) Handler() (http.Handler, error) {
	var err error
	s.page, err = template.ParseFS(assets, "templates/index.html")
	if err != nil {
		return nil, err
	}
	s.static, err = fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /static/{file}", s.asset)
	mux.HandleFunc("POST /api/v1/batches", s.createBatch)
	mux.HandleFunc("GET /api/v1/batches/{id}", s.batchStatus)
	mux.Handle(uploadsPath, s.Uploads)
	return s.headers(s.identify(s.csrf(mux))), nil
}

// headers sets the security headers on every response.
func (s *Server) headers(next http.Handler) http.Handler {
	csp := strings.Join([]string{
		"default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self'",
		"connect-src 'self'", "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'",
		"require-trusted-types-for 'script'", "trusted-types 'none'",
	}, "; ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP uses X-Real-IP only when the direct peer is a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	for _, p := range s.TrustedProxies {
		if p.Contains(peer) {
			if real, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
				return real.Unmap().String()
			}
			break
		}
	}
	return peer.String()
}

func hashSID(sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return hex.EncodeToString(sum[:])
}

func (s *Server) csrfToken(sid string) string {
	m := hmac.New(sha256.New, s.CSRFKey)
	m.Write([]byte("csrf:" + sid))
	return hex.EncodeToString(m.Sum(nil))
}

// identify attaches the session (creating one on the page load) and the
// client IP to the request context.
func (s *Server) identify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sid string
		if c, err := r.Cookie(sessionCookie); err == nil && sidPattern.MatchString(c.Value) {
			sid = c.Value
		}
		if sid == "" && r.Method == http.MethodGet && r.URL.Path == "/" {
			var b [32]byte
			if _, err := rand.Read(b[:]); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			sid = hex.EncodeToString(b[:])
			http.SetCookie(w, &http.Cookie{
				Name: sessionCookie, Value: sid, Path: "/",
				Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
		}
		ctx := r.Context()
		if sid != "" {
			ctx = reqctx.With(ctx, reqctx.Info{SessionHash: hashSID(sid), ClientIP: s.clientIP(r)})
			ctx = withSID(ctx, sid)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrf rejects state-changing requests that lack a session, come from
// another origin, or do not carry the session's CSRF token.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		sid, ok := sidFrom(r.Context())
		if !ok {
			s.reject(w, r, "no_session", "reload the page and try again")
			return
		}
		if r.Header.Get("Origin") != s.PublicOrigin {
			s.reject(w, r, "bad_origin", "request did not come from this site")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			s.reject(w, r, "bad_origin", "request did not come from this site")
			return
		}
		got := r.Header.Get("X-CSRF-Token")
		if !hmac.Equal([]byte(got), []byte(s.csrfToken(sid))) {
			s.reject(w, r, "bad_csrf", "reload the page and try again")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// reject answers 403 and logs why, with what the browser sent next to what
// the server expected. The most common cause in practice is PUBLIC_ORIGIN not
// matching the address users type, and this log line shows both. Header
// values are client-controlled: they are truncated, and the JSON log handler
// escapes them.
func (s *Server) reject(w http.ResponseWriter, r *http.Request, kind, msg string) {
	s.Log.Warn("request rejected",
		"reason", kind,
		"method", r.Method,
		"path", clip(r.URL.Path),
		"client_ip", s.clientIP(r),
		"origin", clip(r.Header.Get("Origin")),
		"expected_origin", s.PublicOrigin,
		"sec_fetch_site", clip(r.Header.Get("Sec-Fetch-Site")),
		"has_csrf_token", r.Header.Get("X-CSRF-Token") != "",
	)
	jsonError(w, http.StatusForbidden, kind, msg)
}

func clip(v string) string {
	if len(v) > 200 {
		return v[:200] + "..."
	}
	return v
}

func jsonError(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, map[string]string{"error": kind, "message": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	enc.Encode(v)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	sid, _ := sidFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	err := s.page.Execute(w, map[string]any{
		"CSRF":          s.csrfToken(sid),
		"Instructions":  s.Instructions,
		"MaxFileSize":   s.MaxFileSize,
		"ChunkSize":     s.ChunkSize,
		"MaxBatchFiles": s.MaxBatchFiles,
	})
	if err != nil {
		s.Log.Error("render page", "err", err)
	}
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !assetPattern.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(s.static, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name))+"; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body")
	}
	if dec.More() {
		return errors.New("invalid JSON body")
	}
	return nil
}

func (s *Server) createBatch(w http.ResponseWriter, r *http.Request) {
	info, _ := reqctx.From(r.Context())
	var req struct {
		Username  string `json:"username"`
		FileCount int    `json:"file_count"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	user, err := names.NormalizeUsername(req.Username)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad_username", err.Error())
		return
	}
	if req.FileCount < 1 || req.FileCount > s.MaxBatchFiles {
		jsonError(w, http.StatusBadRequest, "bad_file_count", "a batch must contain between 1 and the maximum number of files")
		return
	}
	now := time.Now().UTC()
	b := store.Batch{
		ID: names.NewBatchID(now, user), Username: user, ClientIP: info.ClientIP,
		SessionHash: info.SessionHash, FileCount: req.FileCount, CreatedAt: now,
	}
	if err := s.Store.CreateBatch(b); err != nil {
		s.Log.Error("create batch", "err", err)
		jsonError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if err := s.Audit.Append(audit.Event{
		ActorType: "user", Actor: user, Action: "batch.created", BatchID: b.ID,
		Details: map[string]string{"client_ip": info.ClientIP, "file_count": jsonInt(req.FileCount)},
	}); err != nil {
		s.Log.Error("audit append", "err", err)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"batch_id": b.ID, "username": user})
}

func jsonInt(n int) string { b, _ := json.Marshal(n); return string(b) }

// publicState is what users see. Signature names and internal reasons stay
// in the audit log and admin view.
func publicState(st store.State) string {
	switch st {
	case store.StateReceiving:
		return "uploading"
	case store.StateScanning:
		return "scanning"
	case store.StatePassed:
		return "sent"
	case store.StateUnscanned:
		return "sent_unscanned"
	case store.StateQuarantined, store.StateDeleted:
		return "blocked"
	case store.StateHeld:
		return "held"
	case store.StateExpired:
		return "cancelled"
	}
	return "unknown"
}

func (s *Server) batchStatus(w http.ResponseWriter, r *http.Request) {
	info, ok := reqctx.From(r.Context())
	id := r.PathValue("id")
	if !ok || !names.ValidBatchID(id) {
		jsonError(w, http.StatusNotFound, "not_found", "batch not found")
		return
	}
	b, err := s.Store.Batch(id)
	if err != nil || b.SessionHash != info.SessionHash {
		jsonError(w, http.StatusNotFound, "not_found", "batch not found")
		return
	}
	type file struct {
		ID       string `json:"id"`
		Seq      int    `json:"seq"`
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		Received int64  `json:"received"`
		State    string `json:"state"`
		SHA256   string `json:"sha256,omitempty"`
	}
	files := []file{}
	for _, u := range s.Store.BatchUploads(id) {
		files = append(files, file{u.ID, u.Seq, u.OriginalName, u.Size, u.Offset, publicState(u.State), u.SHA256})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"batch_id": b.ID, "username": b.Username, "file_count": b.FileCount,
		"closed": !b.ClosedAt.IsZero(), "files": files,
	})
}
