// Package web serves the embedded map UI and a small JSON/SSE API on localhost.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/store"
	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/whois"
)

//go:embed static
var staticFS embed.FS

// Options of the web server.
type Options struct {
	Listen   string     // default 127.0.0.1:7477 (falls back to a random port)
	Defaults app.Config // template for traces started from the UI
}

// Server is a running web UI.
type Server struct {
	URL  string
	srv  *http.Server
	ln   net.Listener
	opts Options
	st   *store.Store
	run  sync.Mutex
}

// Fragment builds the "#t=id1,id2" URL fragment.
func Fragment(ids []string) string {
	if len(ids) == 0 {
		return "/"
	}
	return "/#t=" + strings.Join(ids, ",")
}

var (
	sharedMu sync.Mutex
	shared   *Server
)

// Shared starts (once) a server for the current process.
func Shared(o Options) (*Server, error) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if shared != nil {
		return shared, nil
	}
	s, err := Start(o)
	if err == nil {
		shared = s
	}
	return s, err
}

// Start listens and serves in the background.
func Start(o Options) (*Server, error) {
	if o.Listen == "" {
		o.Listen = "127.0.0.1:7477"
	}
	ln, err := net.Listen("tcp", o.Listen)
	if err != nil {
		// port busy: pick a random one on the same host
		host, _, _ := net.SplitHostPort(o.Listen)
		if host == "" {
			host = "127.0.0.1"
		}
		ln, err = net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, err
		}
	}
	s := &Server{ln: ln, opts: o, st: store.Default()}
	addr := ln.Addr().(*net.TCPAddr)
	host := addr.IP.String()
	if addr.IP.IsUnspecified() || addr.IP.IsLoopback() {
		host = "127.0.0.1"
	}
	s.URL = fmt.Sprintf("http://%s", net.JoinHostPort(host, strconv.Itoa(addr.Port)))
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/traces", s.handleList)
	mux.HandleFunc("/api/traces/", s.handleGet)
	mux.HandleFunc("/api/diff", s.handleDiff)
	mux.HandleFunc("/api/whois", s.handleWhois)
	mux.HandleFunc("/api/run", s.handleRun)
	s.srv = &http.Server{Handler: s.guard(mux), ReadHeaderTimeout: 10 * time.Second}
	go s.srv.Serve(ln)
	return s, nil
}

// Close stops the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// guard blocks DNS-rebinding and cross-site requests: only loopback Host
// headers are accepted and API calls must be same-origin.
func (s *Server) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(r.Host); err == nil {
			host = hh
		}
		lnHost, _, _ := net.SplitHostPort(s.ln.Addr().String())
		okHost := host == "localhost" || host == "127.0.0.1" || host == "::1" || host == lnHost
		if !okHost {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
			if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	src, n := geo.IXPSource()
	writeJSON(w, map[string]any{"version": app.Version, "ixp_source": src, "ixp_prefixes": n, "cities": geo.CityCount(),
		"domain": "traced.netkitty.dev"})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = 50
	}
	writeJSON(w, s.st.List(n))
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/traces/")
	t, err := s.st.Load(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, t)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.Load(r.URL.Query().Get("a"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	b, err := s.st.Load(r.URL.Query().Get("b"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, store.Compare(a, b))
}

func (s *Server) handleWhois(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > 253 {
		http.Error(w, "q required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, whois.Lookup(ctx, q))
}

var targetRe = func(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	for _, c := range s {
		if !(c == '.' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return !strings.HasPrefix(s, "-")
}

// handleRun starts a trace and streams events as Server-Sent Events.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if !targetRe(target) {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	if !s.run.TryLock() {
		http.Error(w, "a trace is already running", http.StatusConflict)
		return
	}
	defer s.run.Unlock()
	cfg := s.opts.Defaults
	cfg.Trace.Target = target
	switch q.Get("proto") {
	case "tcp":
		cfg.Trace.Protocol = trace.TCP
	case "udp":
		cfg.Trace.Protocol = trace.UDP
	default:
		cfg.Trace.Protocol = trace.ICMP
	}
	if p, err := strconv.Atoi(q.Get("port")); err == nil && p > 0 && p < 65536 {
		cfg.Trace.Port = p
	}
	cfg.Trace.IPv6 = q.Get("v6") == "1"
	cfg.Trace.IPv4 = q.Get("v4") == "1"
	if sni := strings.TrimSpace(q.Get("sni")); sni != "" && targetRe(sni) {
		cfg.SNI = sni
	}
	cfg.Whois = cfg.Geo && app.IsDomain(target)
	cfg.Save = true
	if cfg.Trace.Interface == "" {
		cfg.Trace.Interface = "auto"
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	var wmu sync.Mutex
	send := func(ev trace.Event) {
		b, err := json.Marshal(ev)
		if err != nil {
			return
		}
		wmu.Lock()
		defer wmu.Unlock()
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
		fl.Flush()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	_, err := app.Run(ctx, cfg, send)
	if err != nil && !errors.Is(err, context.Canceled) {
		send(trace.Event{Type: "error", Error: err.Error()})
	}
}

// Static returns the embedded UI files (index.html, app.js, style.css); the
// public share server reuses them in read-only mode.
func Static() fs.FS {
	sub, _ := fs.Sub(staticFS, "static")
	return sub
}
