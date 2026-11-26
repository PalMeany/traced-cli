package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/asn"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/rep"
)

// blob is a pre-encoded, pre-compressed JSON document.
type blob struct {
	raw, gz []byte
	etag    string
	src     *feeds.CableDB
}

var (
	blobMu sync.Mutex
	blobs  = map[string]*blob{}
)

func encodeBlob(v any, src *feeds.CableDB) *blob {
	raw, _ := json.Marshal(v)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write(raw)
	zw.Close()
	h := sha1.Sum(raw)
	return &blob{raw: raw, gz: buf.Bytes(), etag: `"` + hex.EncodeToString(h[:8]) + `"`, src: src}
}

func serveBlob(w http.ResponseWriter, r *http.Request, b *blob, maxAge int) {
	h := w.Header()
	h.Set("Content-Type", "application/geo+json")
	h.Set("ETag", b.etag)
	h.Set("Vary", "Accept-Encoding")
	if maxAge > 0 {
		h.Set("Cache-Control", "public, max-age="+itoa(maxAge))
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == b.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		w.Write(b.gz)
		return
	}
	w.Write(b.raw)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// CableLayer serves /api/cables (kind "cables") and /api/landing (kind
// "landing") from the local cable feed. The first request may build the feed.
func CableLayer(kind string, maxAge int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		db, note := feeds.Cables(ctx)
		if db == nil {
			http.Error(w, "submarine cable map unavailable: "+note, http.StatusServiceUnavailable)
			return
		}
		blobMu.Lock()
		b := blobs[kind]
		if b == nil || b.src != db {
			if kind == "landing" {
				b = encodeBlob(db.LandingGeoJSON(), db)
			} else {
				b = encodeBlob(db.GeoJSON(), db)
			}
			blobs[kind] = b
		}
		blobMu.Unlock()
		if note != "" {
			w.Header().Set("X-Traced-Note", note)
		}
		serveBlob(w, r, b, maxAge)
	}
}

func (s *Server) handleFeeds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, feeds.Stat())
}

// handleASN returns the provider profile, its map brief and the AS reputation.
func (s *Server) handleASN(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > 253 {
		http.Error(w, "q required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	o := asn.Full
	o.Timeout = 15 * time.Second
	rp, err := asn.Lookup(ctx, q, o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ro := rep.DefaultOptions()
	if rp.Routing != nil {
		ro.PrefixesV4, ro.PrefixesV6 = rp.Routing.V4, rp.Routing.V6
	}
	rr := rep.CheckASN(ctx, rp.ASN, ro)
	b := asn.BriefOf(rp, nil, 200)
	b.Rep, b.RepScore = rr.Verdict, rr.Score
	for _, s := range rr.Sources {
		if (s.Status == rep.StListed || s.Status == rep.StInfo) && s.Summary != "" {
			b.RepNotes = append(b.RepNotes, s.Title+": "+s.Summary)
		}
	}
	if rp.Routing != nil { // the full lists are large; the card shows counts
		rp.Routing.V4, rp.Routing.V6 = first(rp.Routing.V4, 50), first(rp.Routing.V6, 20)
	}
	writeJSON(w, map[string]any{"report": rp, "brief": b, "reputation": rr})
}

func first(v []string, n int) []string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func (s *Server) handleRep(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > 253 {
		http.Error(w, "q required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	rr, err := rep.Check(ctx, q, rep.DefaultOptions())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, rr)
}
