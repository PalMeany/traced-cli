package share

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/whois"
)

func sample() *trace.Result {
	return &trace.Result{
		ID: "261126-101010-abc", Target: "one.one.one.one", TargetIP: "1.1.1.1", Protocol: trace.ICMP,
		Started: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC), Reached: true,
		Hops: []trace.Hop{
			{TTL: 1, Sent: 3, Received: 3, Probes: []trace.Probe{{TTL: 1, IP: "192.168.1.1", RTT: 1.2}},
				Responders: []trace.Responder{{IP: "192.168.1.1", RTTs: []float64{1.2}, Geo: &geo.Info{Private: true}}}},
			{TTL: 2, Sent: 3, Received: 3, Final: true, Probes: []trace.Probe{{TTL: 2, IP: "1.1.1.1", RTT: 9.5, Final: true}},
				Responders: []trace.Responder{{IP: "1.1.1.1", RTTs: []float64{9.5}, Final: true,
					Geo:     &geo.Info{City: "Frankfurt", Country: "DE", Lat: 50.1, Lon: 8.7, Located: true, Source: "rdns", Candidates: []geo.Candidate{{}}},
					Network: &whois.ASInfo{ASN: 13335, Name: "CLOUDFLARENET"}}}},
		},
		Extra: &app.Extra{Interface: "en0", Tunnel: "utun4", Notes: []string{"route goes through tunnel utun4"},
			Whois: &whois.Report{Query: "one.one.one.one", Errors: []string{"dial tcp 10.0.0.5:43: refused"}}},
	}
}

func TestSanitizeDropsLocalDetails(t *testing.T) {
	r := sample()
	c, err := Sanitize(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	s := string(b)
	for _, bad := range []string{"en0", "utun4", "tunnel", "10.0.0.5", "261126-101010-abc", "candidates"} {
		if strings.Contains(s, bad) {
			t.Errorf("sanitized trace leaks %q: %s", bad, s)
		}
	}
	for _, good := range []string{"192.168.1.1", "1.1.1.1", "Frankfurt", "13335", "one.one.one.one"} {
		if !strings.Contains(s, good) {
			t.Errorf("sanitized trace lost %q", good)
		}
	}
	// the caller's result is untouched
	if ex := app.ExtraOf(r); ex.Interface != "en0" || len(ex.Whois.Errors) != 1 {
		t.Fatal("Sanitize mutated its input")
	}
	if len(app.InfoOf(&r.Hops[1].Responders[0]).Candidates) != 1 {
		t.Fatal("Sanitize mutated geo info")
	}
}

func TestDecodeRejectsJunkAndRetypes(t *testing.T) {
	for _, in := range []string{`{}`, `{"target":"x","hops":[]}`, `not json`, `{"target":"x","hops":[{"ttl":"<b>"}]}`} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
	// a geo block with wrong types is dropped instead of being passed through
	r, err := Decode([]byte(`{"target":"x","hops":[{"ttl":1,"responders":[{"ip":"1.2.3.4","geo":{"lat":"<img src=x>"},"net":{"asn":"<x>"}}]}],"extra":{"foo":"<script>"}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "<") {
		t.Fatalf("markup survived: %s", b)
	}
}

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := NewServer(ServerOptions{Dir: t.TempDir(), Rate: 3600, Burst: 3, TrustProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	s.o.PublicURL = ts.URL
	return s, ts
}

func TestUploadGetPage(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := Upload(context.Background(), ts.URL, sample())
	if err != nil {
		t.Fatal(err)
	}
	if !validID(resp.ID) || resp.URL != ts.URL+"/t/"+resp.ID {
		t.Fatalf("bad response %+v", resp)
	}
	g, err := http.Get(ts.URL + "/api/traces/" + resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got trace.Result
	json.NewDecoder(g.Body).Decode(&got)
	g.Body.Close()
	if g.StatusCode != 200 || got.ID != resp.ID || len(got.Hops) != 2 || got.TargetIP != "1.1.1.1" {
		t.Fatalf("get: %d %+v", g.StatusCode, got)
	}
	p, _ := http.Get(resp.URL)
	body, _ := io.ReadAll(p.Body)
	p.Body.Close()
	page := string(body)
	if p.StatusCode != 200 || !strings.Contains(page, `data-mode="share"`) || !strings.Contains(page, "/t/assets/app.js") ||
		!strings.Contains(page, "traced → one.one.one.one") {
		t.Fatalf("page: %d %s", p.StatusCode, page)
	}
	for _, a := range []string{"/t/assets/app.js", "/t/assets/style.css", "/api/info"} {
		r, _ := http.Get(ts.URL + a)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Errorf("%s: %d", a, r.StatusCode)
		}
	}
	for _, miss := range []string{"/t/AAAAAAAAAA", "/t/../../etc", "/api/traces/zzz", "/api/traces/..%2f..%2fx"} {
		r, _ := http.Get(ts.URL + miss)
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Errorf("%s: %d", miss, r.StatusCode)
		}
	}
}

func TestLimits(t *testing.T) {
	_, ts := newTestServer(t)
	big := bytes.Repeat([]byte("a"), MaxBody+10)
	r, _ := http.Post(ts.URL+"/api/traces", "application/json", bytes.NewReader(append(append([]byte(`{"target":"`), big...), `"}`...)))
	r.Body.Close()
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %d", r.StatusCode)
	}
	body, _ := json.Marshal(sample())
	codes := []int{}
	for i := 0; i < 4; i++ {
		r, _ := http.Post(ts.URL+"/api/traces", "application/json", bytes.NewReader(body))
		r.Body.Close()
		codes = append(codes, r.StatusCode)
	}
	// burst 3, the oversize request above used one token
	if codes[0] != 201 || codes[1] != 201 || codes[2] != 429 || codes[3] != 429 {
		t.Fatalf("rate limit codes %v", codes)
	}
}

func TestClientIP(t *testing.T) {
	s := &Server{o: ServerOptions{TrustProxy: true}}
	req := func(remote, xreal, cf string) string {
		r := httptest.NewRequest("POST", "/api/traces", nil)
		r.RemoteAddr = remote
		if xreal != "" {
			r.Header.Set("X-Real-IP", xreal)
		}
		if cf != "" {
			r.Header.Set("CF-Connecting-IP", cf)
		}
		return s.ClientIP(r)
	}
	cases := []struct{ remote, xreal, cf, want string }{
		{"127.0.0.1:5000", "172.70.1.1", "203.0.113.7", "203.0.113.7"},    // nginx <- cloudflare
		{"127.0.0.1:5000", "198.51.100.9", "203.0.113.7", "198.51.100.9"}, // nginx <- not cloudflare: header ignored
		{"198.51.100.9:1", "172.70.1.1", "203.0.113.7", "198.51.100.9"},   // X-Real-IP from outside ignored
		{"[2606:4700::1]:443", "", "2001:db8::5", "2001:db8::5"},          // cloudflare v6 directly
		{"127.0.0.1:5000", "", "203.0.113.7", "127.0.0.1"},
	}
	for _, c := range cases {
		if got := req(c.remote, c.xreal, c.cf); got != c.want {
			t.Errorf("%+v: got %s", c, got)
		}
	}
	if rateKey("2001:db8:1:2:3::4") != rateKey("2001:db8:1:2:ffff::1") {
		t.Error("ipv6 rate key is not /64")
	}
}

func TestSweepExpires(t *testing.T) {
	s, ts := newTestServer(t)
	resp, err := Upload(context.Background(), ts.URL, sample())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-31 * 24 * time.Hour)
	p := filepath.Join(s.o.Dir, resp.ID+".json")
	os.Chtimes(p, old, old)
	r, _ := http.Get(ts.URL + "/api/traces/" + resp.ID)
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatalf("expired trace served: %d", r.StatusCode)
	}
	if n := s.Sweep(); n != 1 {
		t.Fatalf("sweep removed %d", n)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file still there")
	}
}

func TestUploadFailureIsAnError(t *testing.T) {
	if _, err := Upload(context.Background(), "http://127.0.0.1:1", sample()); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Upload(context.Background(), "ftp://x", sample()); err == nil {
		t.Fatal("expected error for bad scheme")
	}
}

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if !validID(id) || seen[id] {
			t.Fatalf("bad id %q", id)
		}
		seen[id] = true
	}
}

func TestPublicBackbones(t *testing.T) {
	s, err := NewServer(ServerOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/backbones")
	if err != nil {
		t.Fatal(err)
	}
	var fc struct {
		Type   string           `json:"type"`
		Layers []map[string]any `json:"layers"`
	}
	json.NewDecoder(resp.Body).Decode(&fc)
	resp.Body.Close()
	if resp.StatusCode != 200 || fc.Type != "FeatureCollection" || resp.Header.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("%d %+v", resp.StatusCode, fc)
	}
	// a big upload is refused before parsing
	big := strings.NewReader(strings.Repeat("x", PublicParseBytes+200<<10))
	resp, err = http.Post(ts.URL+"/api/backbone/parse", "multipart/form-data; boundary=zz", big)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 && resp.StatusCode != 400 {
		t.Fatalf("big upload: %d", resp.StatusCode)
	}
}

func TestPublicMapPage(t *testing.T) {
	s, err := NewServer(ServerOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/t/map", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `content="map"`) || !strings.Contains(rec.Body.String(), "/t/assets/app.js") {
		t.Fatalf("%d %.300s", rec.Code, rec.Body.String())
	}
}
