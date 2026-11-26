package rep

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/feeds"
)

func TestVerdictAndAggregate(t *testing.T) {
	cases := []struct {
		srcs  []Source
		score int
		v     string
	}{
		{nil, 0, Clean},
		{[]Source{{Status: StClean}, {Status: StSkipped}, {Status: StError, Score: 99}}, 0, Clean},
		{[]Source{{Status: StInfo, Score: 15}}, 15, LowRisk},
		{[]Source{{Status: StListed, Score: 40}}, 40, Suspicious},
		// FireHOL already contains DROP: overlap adds 5, not 50
		{[]Source{{Status: StListed, Score: 90}, {Status: StListed, Score: 50}}, 95, Dirty},
		{[]Source{{Status: StListed, Score: 40}, {Status: StListed, Score: 50}, {Status: StInfo, Score: 3}}, 55, Suspicious},
		{[]Source{{Status: StListed, Score: 95}, {Status: StListed, Score: 70}, {Status: StListed, Score: 45}}, 100, Dirty},
	}
	for i, c := range cases {
		s, v := Aggregate(c.srcs)
		if s != c.score || v != c.v {
			t.Errorf("case %d: got %d %s want %d %s", i, s, v, c.score, c.v)
		}
	}
	if Verdict(24) != LowRisk || Verdict(25) != Suspicious || Verdict(60) != Dirty {
		t.Fatal("thresholds")
	}
}

func TestParseZen(t *testing.T) {
	// public resolver answer: never a listing
	z := ParseZen([]string{"127.255.255.254"})
	if z.Blocked == "" || len(z.Listed) != 0 {
		t.Fatalf("254: %+v", z)
	}
	if z := ParseZen([]string{"127.255.255.255"}); !strings.Contains(z.Blocked, "excessive") {
		t.Fatalf("255: %+v", z)
	}
	z = ParseZen([]string{"127.0.0.2", "127.0.0.4", "127.0.0.10"})
	if strings.Join(z.Listed, ",") != "PBL,SBL,XBL" || z.Policy || z.Blocked != "" {
		t.Fatalf("multi: %+v", z)
	}
	z = ParseZen([]string{"127.0.0.11", "127.0.0.10"})
	if !z.Policy || len(z.Listed) != 1 {
		t.Fatalf("pbl only: %+v", z)
	}
	if z := ParseZen([]string{"10.0.0.1", "127.1.0.2", "garbage"}); len(z.Listed) != 0 || z.Blocked != "" {
		t.Fatalf("junk: %+v", z)
	}
	if n := ZenName(netip.MustParseAddr("1.2.3.4")); n != "4.3.2.1.zen.spamhaus.org" {
		t.Fatal(n)
	}
	n := ZenName(netip.MustParseAddr("2001:db8::1"))
	if !strings.HasPrefix(n, "1.0.0.0.") || !strings.HasSuffix(n, ".8.b.d.0.1.0.0.2.zen.spamhaus.org") || strings.Count(n, ".") != 34 {
		t.Fatal(n)
	}
}

func TestScores(t *testing.T) {
	addr := feeds.Entry{Prefix: netip.MustParsePrefix("1.2.3.4/32"), Types: []string{"scanner"}}
	sub := feeds.Entry{Prefix: netip.MustParsePrefix("1.2.3.0/24"), Types: []string{"scanner"}}
	brute := feeds.Entry{Prefix: netip.MustParsePrefix("1.2.3.4/32"), Types: []string{"bruteforce"}, Confidence: 1}
	if kinetioScore([]feeds.Entry{sub}) != 30 || kinetioScore([]feeds.Entry{addr, sub}) != 40 || kinetioScore([]feeds.Entry{brute}) != 65 {
		t.Fatal("kinetio ip score")
	}
	// confidence published as percent
	if kinetioScore([]feeds.Entry{{Prefix: addr.Prefix, Confidence: 50}}) != 47 {
		t.Fatal("percent confidence")
	}
	// a big cloud with a handful of scanners stays low; a tiny hoster full of them does not
	big := KinetioASNScore(40, 50_000_000)
	small := KinetioASNScore(40, 4096)
	if big >= small || Verdict(big) != LowRisk || Verdict(small) != Suspicious {
		t.Fatalf("asn density: big=%d small=%d", big, small)
	}
	if KinetioASNScore(0, 1000) != 0 || KinetioASNScore(1, 0) != 5 {
		t.Fatal("asn edge")
	}
	wl := true
	if s := AbuseSource(&AbuseIPDB{Score: 80, Reports: 10, Whitelisted: &wl}); s.Status != StClean {
		t.Fatal("whitelisted")
	}
	if s := AbuseSource(&AbuseIPDB{Score: 80, Reports: 10, Users: 4}); s.Status != StListed || s.Score != 80 {
		t.Fatal("listed")
	}
	if s := AbuseSource(&AbuseIPDB{}); s.Status != StClean {
		t.Fatal("clean")
	}
	if d, err := ParseAbuseIPDB([]byte(`{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":100,"totalReports":3,"numDistinctUsers":2,"isWhitelisted":null}}`)); err != nil || d.Score != 100 {
		t.Fatal(err)
	}
	if _, err := ParseAbuseIPDB([]byte(`{"errors":[{"detail":"Authentication failed."}]}`)); err == nil || !strings.Contains(err.Error(), "Authentication") {
		t.Fatal("error detail")
	}
}

func TestMatchPrefixes(t *testing.T) {
	e, _ := feeds.ParseKinetio([]byte(`{"feed":"public","entries":[
{"network":"5.5.5.1","family":4,"rung":"address","attack_types":["scanner"]},
{"network":"5.5.5.2","family":4,"rung":"address","attack_types":["bruteforce"]},
{"network":"5.5.6.0/24","family":4,"rung":"subnet","attack_types":["scanner","recon"]},
{"network":"6.0.0.1","family":4,"rung":"address","attack_types":["scanner"]}]}`))
	s := feeds.NewSet(e)
	// overlapping announcements (/16 and a more specific /24) count each entry once
	h := MatchPrefixes(s, []string{"5.5.0.0/16", "5.5.5.0/24", "7.0.0.0/8"})
	if h.Inside != 3 || h.Addr != 2 || h.Types["scanner"] != 2 || h.Types["recon"] != 1 {
		t.Fatalf("%+v", h)
	}
	h = MatchPrefixes(s, []string{"5.5.6.128/25"})
	if h.Covering != 1 || h.Inside != 0 {
		t.Fatalf("covering: %+v", h)
	}
}

// seed writes a feed into the cache as if freshly downloaded.
func seed(t *testing.T, name, body string) {
	f := feeds.ByName(name)
	if err := os.WriteFile(cache.File("feeds", name+".dat"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m, _ := json.Marshal(feeds.Meta{URL: f.URL, Fetched: time.Now(), Checked: time.Now(), Entries: 1})
	os.WriteFile(cache.File("feeds", name+".meta.json"), m, 0o644)
}

func TestCheckLocal(t *testing.T) {
	cache.SetDir(t.TempDir())
	defer cache.SetDir("")
	feeds.AutoUpdate = false
	defer func() { feeds.AutoUpdate = true }()
	seed(t, "kinetio", `{"feed":"public","entries":[{"network":"45.1.2.3","family":4,"scope":"global","rung":"address","attack_types":["bruteforce"],"confidence":0},
{"network":"45.9.0.0/24","family":4,"scope":"global","rung":"subnet","attack_types":["scanner"],"confidence":0}]}`)
	seed(t, "spamhaus-drop4", `{"cidr":"46.0.0.0/16","sblid":"SBL1","rir":"ripencc"}`+"\n")
	seed(t, "spamhaus-drop6", `{"cidr":"2a00:dead::/32","sblid":"SBL2","rir":"ripencc"}`+"\n")
	seed(t, "spamhaus-asndrop", `{"asn":64666,"rir":"ripencc","domain":"bad.example","cc":"XX","asname":"BAD-AS"}`+"\n")
	seed(t, "firehol-l1", "46.0.0.0/16\n")
	seed(t, "et-block", "47.0.0.0/24\n")
	seed(t, "tor-exit", "45.1.2.3\n185.220.101.1\n")
	o := Options{NoNetwork: true}

	r := CheckIP(context.Background(), netip.MustParseAddr("45.1.2.3"), o)
	if r.Verdict != Suspicious {
		t.Fatalf("kinetio+tor: %s %d %+v", r.Verdict, r.Score, r.Sources)
	}
	byName := map[string]Source{}
	for _, s := range r.Sources {
		byName[s.Name] = s
	}
	if byName["kinetio"].Status != StListed || byName["tor-exit"].Status != StInfo || byName["abuseipdb"].Status != StSkipped ||
		!strings.Contains(byName["abuseipdb"].Summary, "no API key") {
		t.Fatalf("sources: %+v", r.Sources)
	}
	r = CheckIP(context.Background(), netip.MustParseAddr("46.0.1.1"), o)
	if r.Verdict != Dirty || r.Score != 95 {
		t.Fatalf("drop+firehol: %s %d", r.Verdict, r.Score)
	}
	r = CheckIP(context.Background(), netip.MustParseAddr("2a00:dead::1"), o)
	if r.Verdict != Dirty {
		t.Fatalf("drop v6: %s", r.Verdict)
	}
	r = CheckIP(context.Background(), netip.MustParseAddr("185.220.101.1"), o)
	if r.Verdict != LowRisk {
		t.Fatalf("tor only: %s", r.Verdict)
	}
	r = CheckIP(context.Background(), netip.MustParseAddr("8.8.8.8"), o)
	if r.Verdict != Clean || r.Score != 0 {
		t.Fatalf("clean: %s %+v", r.Verdict, r.Sources)
	}
	if r := CheckIP(context.Background(), netip.MustParseAddr("192.168.1.1"), o); r.Verdict != Clean || len(r.Sources) != 0 {
		t.Fatal("private")
	}
	// AS with given prefixes
	o.PrefixesV4 = []string{"45.1.0.0/16", "45.9.0.0/22"}
	a := CheckASN(context.Background(), 64500, o)
	var kin, ad Source
	for _, s := range a.Sources {
		switch s.Name {
		case "kinetio":
			kin = s
		case "spamhaus-asndrop":
			ad = s
		}
	}
	if a.Verdict == Clean || ad.Status != StClean {
		t.Fatalf("asn: %s %+v", a.Verdict, a.Sources)
	}
	if kin.Matches != 2 || kin.Types["bruteforce"] != 1 {
		t.Fatalf("asn kinetio: %+v", kin)
	}
	o.PrefixesV4 = []string{"203.0.113.0/24"}
	if a := CheckASN(context.Background(), 64666, o); a.Verdict != Dirty || a.ASName != "BAD-AS" {
		t.Fatalf("asndrop: %s %+v", a.Verdict, a.Sources)
	}
	if r, err := Check(context.Background(), "AS64666", o); err != nil || r.Kind != "asn" || r.Verdict != Dirty {
		t.Fatal("dispatch asn", err)
	}
	if _, err := Check(context.Background(), "nonsense", o); err == nil {
		t.Fatal("bad query accepted")
	}
}
