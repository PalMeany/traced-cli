package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/backbone"
)

var (
	bbMu   sync.Mutex
	bbBlob = map[bool]*blob{}
	bbKey  = map[bool]string{}
)

// userLayersKey changes whenever a user layer is added, changed or removed.
func userLayersKey() string {
	ents, _ := os.ReadDir(backbone.Dir())
	var b strings.Builder
	for _, e := range ents {
		if fi, err := e.Info(); err == nil {
			b.WriteString(e.Name() + strconv.FormatInt(fi.ModTime().UnixNano(), 36) + strconv.FormatInt(fi.Size(), 36) + ";")
		}
	}
	return b.String()
}

// BackboneLayer serves /api/backbones: the built-in terrestrial backbone
// dataset, plus the user layers of ~/.cache/traced/backbones when withUser.
func BackboneLayer(withUser bool, maxAge int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := "builtin"
		if withUser {
			key = userLayersKey()
		}
		bbMu.Lock()
		b := bbBlob[withUser]
		if b == nil || bbKey[withUser] != key {
			b = encodeBlob(backbone.Merge(backbone.All(withUser)), nil)
			bbBlob[withUser], bbKey[withUser] = b, key
		}
		bbMu.Unlock()
		serveBlob(w, r, b, maxAge)
	}
}

// ParseLimits restrict /api/backbone/parse.
type ParseLimits struct {
	MaxBytes  int64 // upload size
	MaxPixels int   // decoded picture size
	MaxSide   int   // CV working raster
	AllowSave bool  // "save=1" stores the layer in ~/.cache/traced/backbones
	AllowLLM  bool  // the vision engine may be used (costs API money)
	Offline   bool  // no Nominatim lookups
	Timeout   time.Duration
	Allow     func(r *http.Request) bool // rate limit; nil = always
}

var parseSem = make(chan struct{}, 2)

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// BackboneParse handles POST /api/backbone/parse (multipart: file + the
// fields of `traced backbone parse`). It answers with the layer GeoJSON.
func BackboneParse(l ParseLimits) http.HandlerFunc {
	if l.MaxBytes <= 0 {
		l.MaxBytes = backbone.MaxInput
	}
	if l.Timeout <= 0 {
		l.Timeout = 3 * time.Minute
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, http.StatusMethodNotAllowed, "POST a multipart form")
			return
		}
		if l.Allow != nil && !l.Allow(r) {
			w.Header().Set("Retry-After", "600")
			jsonErr(w, http.StatusTooManyRequests, "rate limit, try later")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, l.MaxBytes+64<<10)
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				jsonErr(w, http.StatusRequestEntityTooLarge, "file too large (limit "+strconv.FormatInt(l.MaxBytes>>20, 10)+" MB)")
				return
			}
			jsonErr(w, http.StatusBadRequest, "multipart form expected: "+err.Error())
			return
		}
		defer r.MultipartForm.RemoveAll()
		f, hdr, err := r.FormFile("file")
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "file field required")
			return
		}
		data, err := io.ReadAll(io.LimitReader(f, l.MaxBytes+1))
		f.Close()
		if err != nil || int64(len(data)) > l.MaxBytes {
			jsonErr(w, http.StatusRequestEntityTooLarge, "file too large (limit "+strconv.FormatInt(l.MaxBytes>>20, 10)+" MB)")
			return
		}
		v := r.FormValue
		provider := strings.TrimSpace(v("provider"))
		if provider == "" || len(provider) > 80 {
			jsonErr(w, http.StatusBadRequest, "provider required (≤80 chars)")
			return
		}
		asn, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(v("asn"))), "AS"))
		if asn < 0 || int64(asn) > 4294967295 {
			asn = 0
		}
		tol, _ := strconv.ParseFloat(v("tolerance"), 64)
		var vision *backbone.VisionConfig
		if l.AllowLLM {
			vision = backbone.VisionFromEnv()
		}
		engine := v("engine")
		if engine == "llm" && vision == nil {
			if l.AllowLLM {
				jsonErr(w, http.StatusBadRequest, "llm engine: no vision API key configured (TRACED_VISION_API_KEY or GEMINI_API_KEY)")
			} else {
				jsonErr(w, http.StatusBadRequest, "llm engine is disabled on this server; use cv or svg")
			}
			return
		}
		name := hdr.Filename
		if len(name) > 120 {
			name = name[:120]
		}
		var gcps []string
		for _, g := range r.MultipartForm.Value["gcp"] {
			if g = strings.TrimSpace(g); g != "" {
				gcps = append(gcps, g)
			}
		}
		if len(gcps) > 16 {
			gcps = gcps[:16]
		}
		opt := backbone.Options{Provider: provider, ASN: asn, Engine: engine, Source: name,
			Ref:      backbone.RefOptions{Region: v("region"), BBox: v("bbox"), GCPs: gcps, Proj: v("proj")},
			CV:       backbone.CVOptions{Color: v("color"), Tolerance: tol, MaxSide: l.MaxSide, MaxPixels: l.MaxPixels},
			SVG:      backbone.SVGOptions{Color: v("color")},
			Vision:   vision,
			Geocoder: &backbone.Geocoder{Offline: l.Offline}}
		select {
		case parseSem <- struct{}{}:
			defer func() { <-parseSem }()
		case <-r.Context().Done():
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), l.Timeout)
		defer cancel()
		g, err := backbone.Parse(ctx, data, opt)
		if err != nil {
			jsonErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		fc := g.GeoJSON()
		out := map[string]any{"layer": fc, "saved": false}
		if v("save") == "1" || v("save") == "true" {
			if !l.AllowSave {
				out["note"] = "layers are not stored on this server: the map keeps it in this browser session"
			} else if _, err := backbone.Save(g); err != nil {
				out["note"] = "save failed: " + err.Error()
			} else {
				out["saved"] = true
			}
		}
		writeJSON(w, out)
	}
}
