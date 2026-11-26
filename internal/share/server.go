package share

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/backbone"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/web"
)

// ServerOptions configure the public trace store.
type ServerOptions struct {
	Dir       string        // storage directory
	PublicURL string        // base of the links handed out, e.g. https://traced.netkitty.dev
	TTL       time.Duration // lifetime of a trace (30 days)
	Rate      int           // uploads per IP per hour
	Burst     int           // uploads allowed at once
	MaxBytes  int64         // total storage cap
	// TrustProxy: requests from loopback come from the local nginx, which
	// passes the peer address in X-Real-IP.
	TrustProxy bool
	Now        func() time.Time
}

// Server is the public share service.
type Server struct {
	o     ServerOptions
	page  string // index.html prepared for share mode
	mux   *http.ServeMux
	lim   *limiter
	plim  *limiter // backbone picture parses
	mu    sync.Mutex
	total int64
}

// PublicParseBytes caps pictures uploaded to the public map importer.
const PublicParseBytes = 4 << 20

const idLen = 10
const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// NewID returns a random base62 id (~59 bits).
func NewID() string {
	b := make([]byte, idLen)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}

func validID(id string) bool {
	if len(id) != idLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(alphabet, rune(id[i])) {
			return false
		}
	}
	return true
}

// NewServer prepares the store directory and the UI.
func NewServer(o ServerOptions) (*Server, error) {
	if o.Dir == "" {
		return nil, errors.New("storage dir required")
	}
	if o.TTL <= 0 {
		o.TTL = 30 * 24 * time.Hour
	}
	if o.Rate <= 0 {
		o.Rate = 30
	}
	if o.Burst <= 0 {
		o.Burst = 10
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 2 << 30
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.PublicURL = strings.TrimRight(o.PublicURL, "/")
	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return nil, err
	}
	idx, err := fs.ReadFile(web.Static(), "index.html")
	if err != nil {
		return nil, err
	}
	page := string(idx)
	page = strings.Replace(page, `<html lang="en">`, `<html lang="en" data-mode="share">`, 1)
	page = strings.Replace(page, `href="style.css"`, `href="/t/assets/style.css"`, 1)
	page = strings.Replace(page, `src="app.js"`, `src="/t/assets/app.js"`, 1)
	s := &Server{o: o, page: page, lim: newLimiter(o.Rate, o.Burst, o.Now), plim: newLimiter(20, 5, o.Now)}
	s.Sweep()
	mux := http.NewServeMux()
	mux.Handle("GET /t/assets/", http.StripPrefix("/t/assets/", http.FileServer(http.FS(web.Static()))))
	mux.HandleFunc("GET /t/map", s.handleMap)
	mux.HandleFunc("GET /t/{id}", s.handlePage)
	mux.HandleFunc("POST /api/traces", s.handleUpload)
	mux.HandleFunc("GET /api/traces/{id}", s.handleGet)
	mux.HandleFunc("GET /api/info", s.handleInfo)
	mux.Handle("GET /api/cables", web.CableLayer("cables", 86400))
	mux.Handle("GET /api/landing", web.CableLayer("landing", 86400))
	mux.Handle("GET /api/asn", web.ASNHandler(func(r *http.Request) bool { return s.lim.allow(s.ClientIP(r)) }))
	mux.Handle("GET /api/bgp", web.BGPHandler(func(r *http.Request) bool { return s.lim.allow(s.ClientIP(r)) }))
	// terrestrial backbones: the built-in dataset only; pictures uploaded on
	// the public map are parsed and handed back, never stored here
	mux.Handle("GET /api/backbones", web.BackboneLayer(false, 3600))
	mux.Handle("POST /api/backbone/parse", web.BackboneParse(web.ParseLimits{MaxBytes: PublicParseBytes, MaxPixels: 16_000_000,
		MaxSide: 1800, AllowLLM: os.Getenv("TRACED_PUBLIC_LLM") == "1", Timeout: 90 * time.Second,
		Allow: func(r *http.Request) bool { return s.plim.allow(s.ClientIP(r)) }}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	s.mux = mux
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; "+
		"style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: blob: https:; "+
		"connect-src 'self' https:; worker-src 'self' blob:; child-src blob:; font-src 'self' https: data:; "+
		"frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	s.mux.ServeHTTP(w, r)
}

// Run sweeps expired traces every hour until stop is closed.
// It also keeps the submarine cable map (served on /api/cables) fresh.
func (s *Server) Run(stop <-chan struct{}) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	go s.refreshCables()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.Sweep()
			s.lim.gc()
			go s.refreshCables()
			s.plim.gc()
		}
	}
}

var refreshing sync.Mutex

func (s *Server) refreshCables() {
	if !refreshing.TryLock() {
		return
	}
	defer refreshing.Unlock()
	if st := feedStatus("cables"); st != nil && st.Fresh {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r := feeds.Update(ctx, feeds.ByName("cables"))
	if r.Err != nil {
		log.Printf("cables: refresh failed: %v", r.Err)
	} else if r.Updated {
		log.Printf("cables: %d cables refreshed in %s", r.Entries, r.Took.Round(time.Second))
	}
}

func feedStatus(name string) *feeds.Status {
	for _, st := range feeds.Stat() {
		if st.Name == name {
			return &st
		}
	}
	return nil
}

// Sweep deletes expired traces and recounts the storage in use.
func (s *Server) Sweep() int {
	ents, _ := os.ReadDir(s.o.Dir)
	var total int64
	n := 0
	now := s.o.Now()
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(s.o.Dir, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if strings.HasSuffix(e.Name(), ".tmp") && now.Sub(fi.ModTime()) > time.Hour ||
			strings.HasSuffix(e.Name(), ".json") && now.Sub(fi.ModTime()) > s.o.TTL {
			if os.Remove(p) == nil {
				n++
			}
			continue
		}
		total += fi.Size()
	}
	s.mu.Lock()
	s.total = total
	s.mu.Unlock()
	if n > 0 {
		log.Printf("sweep: removed %d expired traces, %d KB in use", n, total>>10)
	}
	return n
}

func (s *Server) path(id string) string { return filepath.Join(s.o.Dir, id+".json") }

// load returns the stored JSON and its expiry, or an error when missing/expired.
func (s *Server) load(id string) ([]byte, time.Time, error) {
	if !validID(id) {
		return nil, time.Time{}, fs.ErrNotExist
	}
	fi, err := os.Stat(s.path(id))
	if err != nil {
		return nil, time.Time{}, fs.ErrNotExist
	}
	exp := fi.ModTime().Add(s.o.TTL)
	if s.o.Now().After(exp) {
		return nil, time.Time{}, fs.ErrNotExist
	}
	b, err := os.ReadFile(s.path(id))
	return b, exp, err
}

func (s *Server) publicBase(r *http.Request) string {
	if s.o.PublicURL != "" {
		return s.o.PublicURL
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	ip := s.ClientIP(r)
	if !s.lim.allow(ip) {
		w.Header().Set("Retry-After", "600")
		jsonError(w, http.StatusTooManyRequests, "rate limit, try later")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		jsonError(w, http.StatusUnsupportedMediaType, "application/json expected")
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		jsonError(w, http.StatusRequestEntityTooLarge, "trace too large (limit 512 KB)")
		return
	}
	tr, err := Decode(b)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := NewID()
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(s.path(id)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		id = NewID()
	}
	tr.ID = id
	out, err := json.Marshal(tr)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "encode failed")
		return
	}
	s.mu.Lock()
	full := s.total+int64(len(out)) > s.o.MaxBytes
	if !full {
		s.total += int64(len(out))
	}
	s.mu.Unlock()
	if full {
		jsonError(w, http.StatusInsufficientStorage, "storage full, try later")
		return
	}
	tmp := s.path(id) + ".tmp"
	if err := os.WriteFile(tmp, out, 0o640); err != nil {
		jsonError(w, http.StatusInternalServerError, "store failed")
		return
	}
	if err := os.Rename(tmp, s.path(id)); err != nil {
		os.Remove(tmp)
		jsonError(w, http.StatusInternalServerError, "store failed")
		return
	}
	log.Printf("stored %s %s (%d hops, %d B) from %s", id, tr.Target, len(tr.Hops), len(out), anonIP(ip))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", "/t/"+id)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Response{ID: id, URL: s.publicBase(r) + "/t/" + id, Expires: s.o.Now().Add(s.o.TTL).UTC().Truncate(time.Second)})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	b, exp, err := s.load(r.PathValue("id"))
	if err != nil {
		jsonError(w, http.StatusNotFound, "trace not found or expired")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Expires", exp.UTC().Format(http.TimeFormat))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(b)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	src, n := geo.IXPSource()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"version": app.Version, "ixp_source": src, "ixp_prefixes": n,
		"cities": geo.CityCount(), "share": true, "ttl_days": int(s.o.TTL.Hours() / 24),
		"backbone_parse_mb": PublicParseBytes >> 20, "backbone_llm": os.Getenv("TRACED_PUBLIC_LLM") == "1" && backbone.VisionFromEnv() != nil})
}

const notFoundPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>traced — trace not found</title><style>body{margin:0;background:#0b0e13;color:#d7dee8;font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}
main{max-width:520px;padding:24px}a{color:#5cc8ff}code{background:#161d27;padding:2px 6px;border-radius:4px}</style></head><body><main>
<h1>Trace not found</h1><p>The link is wrong or the trace has expired (shared traces live %d days).</p>
<p>Run your own: <code>curl -sL traced.netkitty.dev | sh -s -- 1.1.1.1</code></p><p><a href="/">traced.netkitty.dev</a></p></main></body></html>`

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	b, _, err := s.load(id)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, notFoundPage, int(s.o.TTL.Hours()/24))
		return
	}
	title, desc := "traced — shared trace", "Traceroute on a map"
	if tr, err := Decode(b); err == nil {
		last := tr.Hops[len(tr.Hops)-1]
		state := "reached"
		if !tr.Reached {
			state = "not reached"
		}
		title = fmt.Sprintf("traced → %s", tr.Target)
		desc = fmt.Sprintf("%s %s, %d hops, %s, %.1f ms — route map with ASN, cities and RTT",
			strings.ToUpper(string(tr.Protocol)), tr.TargetIP, len(tr.Hops), state, last.AvgRTT())
	}
	meta := fmt.Sprintf(`<title>%s</title>
<meta name="description" content="%s">
<meta property="og:title" content="%s">
<meta property="og:description" content="%s">
<meta property="og:type" content="website">
<meta property="og:url" content="%s">
<meta name="traced-share" content="%s">`,
		html.EscapeString(title), html.EscapeString(desc), html.EscapeString(title), html.EscapeString(desc),
		html.EscapeString(s.publicBase(r)+"/t/"+id), html.EscapeString(id))
	page := strings.Replace(s.page, "<title>traced — route map</title>", meta, 1)
	w.Header().Set("Cache-Control", "public, max-age=300")
	io.WriteString(w, page)
}

// handleMap is the public map without a trace: submarine cables, the
// terrestrial backbone dataset and the picture importer.
func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	meta := `<title>traced — backbone & cable map</title>
<meta name="description" content="Terrestrial Internet backbones of major providers and submarine cables on one map; import a provider's network map picture.">
<meta property="og:title" content="traced — backbone & cable map">
<meta name="traced-share" content="map">`
	page := strings.Replace(s.page, "<title>traced — route map</title>", meta, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	io.WriteString(w, page)
}

// ---------------- client address & rate limit ----------------

// cloudflare edge ranges (https://www.cloudflare.com/ips/)
var cfNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32",
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// IsCloudflare reports whether ip belongs to a Cloudflare edge range.
func IsCloudflare(ip net.IP) bool {
	for _, n := range cfNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the address used for rate limiting. CF-Connecting-IP is
// believed only when the connecting peer is a Cloudflare edge; behind the
// local nginx the peer comes from X-Real-IP (set by nginx, never by clients).
func (s *Server) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer != nil && peer.IsLoopback() && s.o.TrustProxy {
		if xr := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); xr != nil {
			peer = xr
		}
	}
	if peer == nil {
		return host
	}
	if IsCloudflare(peer) {
		if c := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); c != nil {
			return c.String()
		}
	}
	return peer.String()
}

// rate key: IPv4 address or IPv6 /64
func rateKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() != nil {
		return ip
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// anonIP keeps logs coarse: /24 for IPv4, /48 for IPv6.
func anonIP(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return "?"
	}
	if p4 := p.To4(); p4 != nil {
		return p4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return p.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time
	m     map[string]*bucket
}

func newLimiter(perHour, burst int, now func() time.Time) *limiter {
	return &limiter{rate: float64(perHour) / 3600, burst: float64(burst), now: now, m: map[string]*bucket{}}
}

func (l *limiter) allow(ip string) bool {
	k := rateKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.m[k]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.m[k] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) gc() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.m {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.m, k)
		}
	}
}
