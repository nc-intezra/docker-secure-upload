// Package tus implements the core of the tus 1.0.0 resumable upload protocol
// with the creation and termination extensions
// (https://tus.io/protocols/resumable-upload).
//
// It is written for this service rather than taken from tusd so that the
// SHA-256 can be computed as chunks arrive: after every chunk the hasher's
// internal state is saved with the upload record, so a resumed upload
// continues the hash without re-reading what is already on disk.
//
// Callers must put session information in the request context (package
// reqctx) and check CSRF before requests reach this handler.
package tus

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nc-intezra/docker-secure-upload/internal/audit"
	"github.com/nc-intezra/docker-secure-upload/internal/fsutil"
	"github.com/nc-intezra/docker-secure-upload/internal/names"
	"github.com/nc-intezra/docker-secure-upload/internal/reqctx"
	"github.com/nc-intezra/docker-secure-upload/internal/store"
)

const version = "1.0.0"

// Pipeline is what the handler hands completed and cancelled uploads to.
type Pipeline interface {
	Enqueue(id string)
	Finish(u store.Upload)
}

// Handler serves POST, HEAD, PATCH, DELETE and OPTIONS under BasePath.
type Handler struct {
	BasePath    string // e.g. "/api/v1/uploads/"
	IncomingDir string
	Store       *store.Store
	Audit       *audit.Log
	Pipeline    Pipeline
	MaxFileSize int64
	ChunkSize   int64
	DiskReserve int64
	RejectAbove int64 // refuse uploads larger than this at creation; 0 = no limit
	Log         *slog.Logger
	FreeBytes   func(path string) (int64, error) // defaults to fsutil.FreeBytes
	locks       sync.Map
	now         func() time.Time
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (h *Handler) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now().UTC()
}

func (h *Handler) logger() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Tus-Resumable", version)
	w.Header().Set("Cache-Control", "no-store")

	if r.Method == http.MethodOptions {
		w.Header().Set("Tus-Version", version)
		w.Header().Set("Tus-Extension", "creation,termination")
		w.Header().Set("Tus-Max-Size", strconv.FormatInt(h.MaxFileSize, 10))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Header.Get("Tus-Resumable") != version {
		w.Header().Set("Tus-Version", version)
		httpError(w, http.StatusPreconditionFailed, "unsupported tus version")
		return
	}
	info, ok := reqctx.From(r.Context())
	if !ok {
		httpError(w, http.StatusForbidden, "no session")
		return
	}

	rest, ok := strings.CutPrefix(r.URL.Path, h.BasePath)
	if !ok {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	if rest == "" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST, OPTIONS")
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.create(w, r, info)
		return
	}
	if !idPattern.MatchString(rest) {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	u, err := h.Store.Upload(rest)
	// Someone else's upload looks exactly like a missing one.
	if err != nil || u.SessionHash != info.SessionHash {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	switch r.Method {
	case http.MethodHead:
		h.head(w, u)
	case http.MethodPatch:
		h.patch(w, r, u)
	case http.MethodDelete:
		h.terminate(w, u)
	default:
		w.Header().Set("Allow", "HEAD, PATCH, DELETE, OPTIONS")
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	io.WriteString(w, msg+"\n")
}

// parseMetadata decodes "key base64,key base64". Only known keys are
// accepted and each decoded value is limited to 1 KiB.
func parseMetadata(s string) (map[string]string, error) {
	out := map[string]string{}
	if len(s) > 4096 {
		return nil, errors.New("metadata too long")
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, " ")
		switch k {
		case "batch_id", "filename":
		default:
			return nil, fmt.Errorf("unknown metadata key %q", k)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate metadata key %q", k)
		}
		dec, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(dec) > 1024 {
			return nil, fmt.Errorf("bad value for %q", k)
		}
		out[k] = string(dec)
	}
	return out, nil
}

// errBatchFull and friends map to HTTP statuses in create.
var (
	errBatchFull   = errors.New("batch already has all its declared files")
	errBatchClosed = errors.New("batch is closed")
)

func (h *Handler) create(w http.ResponseWriter, r *http.Request, info reqctx.Info) {
	if r.Header.Get("Upload-Defer-Length") != "" {
		httpError(w, http.StatusBadRequest, "Upload-Length is required")
		return
	}
	if r.ContentLength > 0 {
		httpError(w, http.StatusBadRequest, "send data with PATCH after creating the upload")
		return
	}
	size, err := strconv.ParseInt(r.Header.Get("Upload-Length"), 10, 64)
	if err != nil || size < 0 {
		httpError(w, http.StatusBadRequest, "invalid Upload-Length")
		return
	}
	if size > h.MaxFileSize {
		httpError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file is larger than the %d-byte limit", h.MaxFileSize))
		return
	}
	if h.RejectAbove > 0 && size > h.RejectAbove {
		httpError(w, http.StatusRequestEntityTooLarge, "file is too large to be virus-scanned and the oversize policy is reject")
		return
	}
	meta, err := parseMetadata(r.Header.Get("Upload-Metadata"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	batchID := meta["batch_id"]
	if !names.ValidBatchID(batchID) {
		httpError(w, http.StatusBadRequest, "invalid batch_id")
		return
	}
	original, err := names.CleanOriginal(meta["filename"])
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	b, err := h.Store.Batch(batchID)
	if err != nil || b.SessionHash != info.SessionHash {
		httpError(w, http.StatusNotFound, "batch not found")
		return
	}

	if err := h.checkDisk(size); err != nil {
		h.logger().Warn("upload refused: disk", "err", err)
		httpError(w, http.StatusInsufficientStorage, "not enough staging space; try again later")
		return
	}

	var rb [16]byte
	if _, err := rand.Read(rb[:]); err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	id := hex.EncodeToString(rb[:])
	path := filepath.Join(h.IncomingDir, id)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fsutil.FileMode)
	if err != nil {
		h.logger().Error("create staging file", "err", err)
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	f.Close()

	now := h.clock()
	u := store.Upload{
		ID: id, BatchID: batchID, Username: b.Username, ClientIP: info.ClientIP,
		SessionHash: info.SessionHash, OriginalName: original, Size: size,
		State: store.StateReceiving, CreatedAt: now, UpdatedAt: now,
	}
	if size == 0 {
		sum := sha256.Sum256(nil)
		u.SHA256 = hex.EncodeToString(sum[:])
		u.State = store.StateScanning
		u.CompletedAt = now
	}
	u, err = h.Store.CreateUpload(u, func(b *store.Batch, u *store.Upload, seq int) error {
		if !b.ClosedAt.IsZero() {
			return errBatchClosed
		}
		if b.Created >= b.FileCount {
			return errBatchFull
		}
		u.OutboxName = names.OutboxName(b.ID, seq, u.OriginalName)
		return nil
	})
	if err != nil {
		os.Remove(path)
		switch {
		case errors.Is(err, errBatchFull), errors.Is(err, errBatchClosed):
			httpError(w, http.StatusConflict, err.Error())
		default:
			h.logger().Error("create upload record", "err", err)
			httpError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	h.audit("upload.created", u, map[string]string{"size": strconv.FormatInt(size, 10), "original_name": original})
	if u.State == store.StateScanning {
		h.audit("upload.received", u, map[string]string{"sha256": u.SHA256})
		h.Pipeline.Enqueue(u.ID)
	}
	w.Header().Set("Location", h.BasePath+id)
	w.Header().Set("Upload-Offset", "0")
	w.WriteHeader(http.StatusCreated)
}

// checkDisk refuses an upload unless the staging filesystem can hold it,
// every other unfinished upload, and the configured reserve.
func (h *Handler) checkDisk(size int64) error {
	free := h.FreeBytes
	if free == nil {
		free = fsutil.FreeBytes
	}
	avail, err := free(h.IncomingDir)
	if err != nil {
		return err
	}
	var pending int64
	for _, u := range h.Store.UploadsIn(store.StateReceiving) {
		pending += u.Size - u.Offset
	}
	if need := pending + size + h.DiskReserve; need > avail {
		return fmt.Errorf("need %d bytes, %d available", need, avail)
	}
	return nil
}

func (h *Handler) head(w http.ResponseWriter, u store.Upload) {
	off := u.Offset
	if u.State != store.StateReceiving {
		off = u.Size
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(off, 10))
	w.Header().Set("Upload-Length", strconv.FormatInt(u.Size, 10))
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) lock(id string) *sync.Mutex {
	m, _ := h.locks.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request, u store.Upload) {
	if r.Header.Get("Content-Type") != "application/offset+octet-stream" {
		httpError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/offset+octet-stream")
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		httpError(w, http.StatusBadRequest, "invalid Upload-Offset")
		return
	}
	mu := h.lock(u.ID)
	if !mu.TryLock() {
		httpError(w, http.StatusLocked, "another request is writing to this upload")
		return
	}
	defer mu.Unlock()

	u, err = h.Store.Upload(u.ID) // re-read under the lock
	if err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	if u.State != store.StateReceiving {
		httpError(w, http.StatusConflict, "upload is already complete")
		return
	}
	if offset != u.Offset {
		w.Header().Set("Upload-Offset", strconv.FormatInt(u.Offset, 10))
		httpError(w, http.StatusConflict, "Upload-Offset does not match")
		return
	}
	limit := min(h.ChunkSize, u.Size-u.Offset)
	if r.ContentLength > limit {
		httpError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("chunk may be at most %d bytes", limit))
		return
	}

	hasher, err := restoreHash(u.HashState)
	if err != nil {
		h.logger().Error("restore hash state", "upload", u.ID, "err", err)
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	f, err := os.OpenFile(filepath.Join(h.IncomingDir, u.ID), os.O_WRONLY, 0)
	if err != nil {
		h.logger().Error("open staging file", "upload", u.ID, "err", err)
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Write to the file first and the hasher second, so the hash only
	// covers bytes that reached the file. A short body (client gone) still
	// commits what arrived, as tus expects.
	n, copyErr := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(r.Body, limit))
	if copyErr == nil && n == limit {
		var one [1]byte
		if m, _ := r.Body.Read(one[:]); m > 0 {
			httpError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("chunk may be at most %d bytes", limit))
			return
		}
	}
	if n == 0 && copyErr != nil {
		httpError(w, http.StatusBadRequest, "no data received")
		return
	}
	if err := f.Sync(); err != nil {
		h.logger().Error("sync staging file", "upload", u.ID, "err", err)
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	state, err := hasher.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	newOffset := offset + n
	complete := newOffset == u.Size
	sum := ""
	if complete {
		sum = hex.EncodeToString(hasher.Sum(nil))
	}
	u, err = h.Store.UpdateUpload(u.ID, func(x *store.Upload) error {
		if x.State != store.StateReceiving || x.Offset != offset {
			return errors.New("upload changed concurrently")
		}
		x.Offset = newOffset
		if complete {
			x.HashState = nil
			x.SHA256 = sum
			x.State = store.StateScanning
			x.CompletedAt = h.clock()
		} else {
			x.HashState = state
		}
		return nil
	})
	if err != nil {
		h.logger().Error("save upload progress", "upload", u.ID, "err", err)
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if complete {
		h.audit("upload.received", u, map[string]string{"sha256": sum, "size": strconv.FormatInt(u.Size, 10)})
		h.Pipeline.Enqueue(u.ID)
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(newOffset, 10))
	w.WriteHeader(http.StatusNoContent)
}

func restoreHash(state []byte) (hash.Hash, error) {
	hs := sha256.New()
	if len(state) == 0 {
		return hs, nil
	}
	if err := hs.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return nil, err
	}
	return hs, nil
}

func (h *Handler) terminate(w http.ResponseWriter, u store.Upload) {
	mu := h.lock(u.ID)
	mu.Lock()
	defer mu.Unlock()
	u, err := h.Store.UpdateUpload(u.ID, func(x *store.Upload) error {
		if x.State != store.StateReceiving {
			return errors.New("complete")
		}
		x.State = store.StateExpired
		x.ScanReason = "cancelled by user"
		return nil
	})
	if err != nil {
		httpError(w, http.StatusConflict, "upload is already complete")
		return
	}
	h.audit("upload.cancelled", u, nil)
	h.Pipeline.Finish(u)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) audit(action string, u store.Upload, details map[string]string) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Append(audit.Event{
		ActorType: "user", Actor: u.Username, Action: action,
		UploadID: u.ID, BatchID: u.BatchID, Details: details,
	}); err != nil {
		h.logger().Error("audit append", "action", action, "err", err)
	}
}
