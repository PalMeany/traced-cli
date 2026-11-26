package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
)

const kinetioSample = `{
  "feed": "public",
  "entries": [
    {"network": "1.0.140.95", "family": 4, "scope": "global", "rung": "address", "attack_types": ["scanner"], "confidence": 0},
    {"network": "2.57.17.0/24", "family": 4, "scope": "global", "rung": "subnet", "attack_types": ["scanner", "recon"], "confidence": 0.4},
    {"network": "2.57.17.9", "family": 4, "scope": "global", "rung": "address", "attack_types": ["bruteforce"], "confidence": 0.9},
    {"network": "1.0.140.95", "family": 4, "scope": "global", "rung": "address", "attack_types": ["exploit_attempt"], "confidence": 0.7},
    {"network": "2604:a880:400:d1::/64", "family": 6, "scope": "global", "rung": "subnet", "attack_types": ["scanner"], "confidence": 0},
    {"network": "not-an-ip", "family": 4, "scope": "global", "rung": "address", "attack_types": ["scanner"], "confidence": 0},
    {"network": "10.0.0.1", "family": 6, "scope": "global", "rung": "address", "attack_types": ["scanner"], "confidence": 0}
  ]
}`

func TestParseKinetio(t *testing.T) {
	e, err := ParseKinetio([]byte(kinetioSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 5 { // bad address and family mismatch dropped
		t.Fatalf("entries %d, want 5", len(e))
	}
	s := NewSet(e)
	if s.Len() != 4 { // duplicate 1.0.140.95 merged
		t.Fatalf("set len %d, want 4", s.Len())
	}
	hit := s.Lookup(netip.MustParseAddr("1.0.140.95"))
	if len(hit) != 1 || strings.Join(hit[0].Types, ",") != "exploit_attempt,scanner" || hit[0].Confidence != 0.7 {
		t.Fatalf("merged entry wrong: %+v", hit)
	}
	// address inside the /24 matches both the address and the subnet, most specific first
	hit = s.Lookup(netip.MustParseAddr("2.57.17.9"))
	if len(hit) != 2 || hit[0].Prefix.Bits() != 32 || hit[1].Prefix.Bits() != 24 || hit[1].Rung != "subnet" {
		t.Fatalf("lookup 2.57.17.9: %+v", hit)
	}
	if !s.Contains(netip.MustParseAddr("2.57.17.200")) || s.Contains(netip.MustParseAddr("2.57.18.1")) {
		t.Fatal("subnet containment wrong")
	}
	if !s.Contains(netip.MustParseAddr("2604:a880:400:d1::42")) || s.Contains(netip.MustParseAddr("2604:a880:400:d2::1")) {
		t.Fatal("v6 containment wrong")
	}
	// 4-in-6 queries are unmapped
	if !s.Contains(netip.MustParseAddr("::ffff:1.0.140.95")) {
		t.Fatal("4in6 not unmapped")
	}
	if _, err := ParseKinetio([]byte(`{"feed":"public"}`)); err == nil {
		t.Fatal("missing entries should fail")
	}
}

func TestSetOverlap(t *testing.T) {
	e, _ := ParseNetset(strings.NewReader("# c\n10.0.0.0/8\n10.1.2.3\n10.1.3.0/24 ; note\n11.0.0.1\n2001:db8::1\n\n"), "x")
	s := NewSet(e)
	in, cov := s.Overlap(netip.MustParsePrefix("10.1.0.0/16"))
	if len(in) != 2 || len(cov) != 1 || cov[0].Prefix.String() != "10.0.0.0/8" {
		t.Fatalf("overlap 10.1/16: in=%v cov=%v", in, cov)
	}
	in, cov = s.Overlap(netip.MustParsePrefix("11.0.0.0/24"))
	if len(in) != 1 || len(cov) != 0 {
		t.Fatalf("overlap 11/24: in=%v cov=%v", in, cov)
	}
	in, _ = s.Overlap(netip.MustParsePrefix("2001:db8::/32"))
	if len(in) != 1 {
		t.Fatalf("v6 overlap: %v", in)
	}
	in, cov = s.Overlap(netip.MustParsePrefix("12.0.0.0/8"))
	if len(in)+len(cov) != 0 {
		t.Fatal("no overlap expected")
	}
	// the network itself counts as inside, not covering
	in, cov = s.Overlap(netip.MustParsePrefix("10.0.0.0/8"))
	if len(in) != 3 || len(cov) != 0 {
		t.Fatalf("self overlap: in=%v cov=%v", in, cov)
	}
}

func TestParseSpamhaus(t *testing.T) {
	drop := `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}
{"type":"metadata","timestamp":1795613204,"size":105931,"records":2}
`
	e, err := ParseSpamhausDROP([]byte(drop))
	if err != nil || len(e) != 2 || e[0].Ref != "SBL256894" {
		t.Fatalf("drop json: %v %+v", err, e)
	}
	legacy := "; Spamhaus DROP List\n1.10.16.0/20 ; SBL256894\n1.19.0.0/16 ; SBL434604\n"
	e, err = ParseSpamhausDROP([]byte(legacy))
	if err != nil || len(e) != 2 || e[1].Ref != "SBL434604" {
		t.Fatalf("drop txt: %v %+v", err, e)
	}
	s := NewSet(e)
	if !s.Contains(netip.MustParseAddr("1.10.20.1")) {
		t.Fatal("drop lookup")
	}
	asn := `{"asn":245,"rir":"arin","domain":"planningresearchcorp.com","cc":"US","asname":"PRC-AS"}
{"asn":2601,"rir":"ripencc","domain":"pitline.net","cc":"UA","asname":"RADIOLINK-AS"}
{"type":"metadata","timestamp":1,"records":2}
`
	m, err := ParseASNDrop([]byte(asn))
	if err != nil || len(m) != 2 || m[2601].Name != "RADIOLINK-AS" || m[245].CC != "US" {
		t.Fatalf("asndrop: %v %+v", err, m)
	}
	m, _ = ParseASNDrop([]byte("; ASN-DROP\nAS245 ; US | PRC-AS\n"))
	if m[245].Name != "PRC-AS" || m[245].CC != "US" {
		t.Fatalf("asndrop txt: %+v", m)
	}
}

func TestParseASPop(t *testing.T) {
	j := `{"copyright":"x","Date":"24/11/2026","Window":"60 Days","Data":[
{"rank":1,"AS":55836,"Description":"RELIANCEJIO-IN","CC":"IN","Users":284764639,"Percent of CC Pop":48.21,"Percent of Internet":6.8239,"Samples":82242816},
{"rank":900,"AS":13335,"Description":"CLOUDFLARENET","CC":"US","Users":1000,"Percent of CC Pop":0.01,"Percent of Internet":0.0001,"Samples":10},
{"rank":40,"AS":13335,"Description":"CLOUDFLARENET","CC":"DE","Users":50000,"Percent of CC Pop":0.1,"Percent of Internet":0.001,"Samples":99}]}`
	m, date, err := ParseASPop(strings.NewReader(j))
	if err != nil || date != "24/11/2026" {
		t.Fatal(err, date)
	}
	if len(m[13335]) != 2 || m[13335][0].CC != "DE" || m[55836][0].PctCountry != 48.21 {
		t.Fatalf("aspop: %+v", m)
	}
}

const cableGeo = `{"type":"FeatureCollection","features":[
{"type":"Feature","properties":{"id":"atl-1","name":"Atlantic One","color":"#ff0000","feature_id":"atl-1-0"},
 "geometry":{"type":"MultiLineString","coordinates":[[[-74.0,40.7],[-40.0,45.0]]]}},
{"type":"Feature","properties":{"id":"atl-1","name":"Atlantic One","color":"#ff0000","feature_id":"atl-1-1"},
 "geometry":{"type":"MultiLineString","coordinates":[[[-40.0,45.0],[-5.5,50.1]]]}},
{"type":"Feature","properties":{"id":"baltic","name":"Baltic Short","color":"#00ff00"},
 "geometry":{"type":"LineString","coordinates":[[24.9,60.1],[18.0,59.3]]}},
{"type":"Feature","properties":{"id":"future","name":"Future Cable","color":"#0000ff"},
 "geometry":{"type":"LineString","coordinates":[[-74.0,40.6],[-5.0,50.0]]}}
]}`

const landingGeo = `{"type":"FeatureCollection","features":[
{"type":"Feature","properties":{"id":"nyc","name":"New York, NY, United States"},"geometry":{"type":"Point","coordinates":[-73.95,40.65]}},
{"type":"Feature","properties":{"id":"bude","name":"Bude, United Kingdom"},"geometry":{"type":"Point","coordinates":[-4.54,50.83]}},
{"type":"Feature","properties":{"id":"hel","name":"Helsinki, Finland"},"geometry":{"type":"Point","coordinates":[24.94,60.17]}},
{"type":"Feature","properties":{"id":"sto","name":"Stockholm, Sweden"},"geometry":{"type":"Point","coordinates":[18.06,59.33]}}
]}`

func testCableDB(t *testing.T) *CableDB {
	cs, err := ParseCableGeo([]byte(cableGeo))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 || len(cs[0].Geometry) != 2 {
		t.Fatalf("cables merged wrong: %+v", cs)
	}
	lps, err := ParseLandingGeo([]byte(landingGeo))
	if err != nil || len(lps) != 4 || lps[1].Country != "United Kingdom" {
		t.Fatalf("landing: %v %+v", err, lps)
	}
	details := map[string]*CableDetail{
		"atl-1":  {Name: "Atlantic One", Length: "6,500 km", RFS: "2001", RFSYear: 2001},
		"baltic": {Length: "400 km", RFS: "1999"},
		"future": {Length: "7,000 km", RFS: "2029", IsPlanned: true},
	}
	details["atl-1"].LandingPoints = append(details["atl-1"].LandingPoints, struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Country string `json:"country"`
	}{ID: "nyc"}, struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Country string `json:"country"`
	}{ID: "bude"})
	details["future"].LandingPoints = details["atl-1"].LandingPoints
	for i := range cs {
		cs[i].Apply(details[cs[i].ID])
	}
	return &CableDB{Cables: cs, Landing: lps}
}

func TestCablesAndSuggest(t *testing.T) {
	db := testCableDB(t)
	if LengthKm(db.Cables[0].Length) != 6500 {
		t.Fatal("length parse")
	}
	// New York → London: Atlantic One lands at NYC and Bude (≈300 km from London)
	h := db.Suggest(40.71, -74.0, 51.5, -0.12, 3)
	if len(h) != 1 || h[0].ID != "atl-1" || h[0].FromName != "New York, NY, United States" || h[0].ToKm > 350 {
		t.Fatalf("suggest: %+v", h)
	}
	// short segments get no hint
	if h := db.Suggest(60.17, 24.94, 59.33, 18.06, 3); h != nil {
		t.Fatalf("short segment hint: %+v", h)
	}
	// both ends inland and far from any station: nothing
	if h := db.Suggest(39.7, -105.0, 48.1, 11.6, 3); h != nil {
		t.Fatalf("inland hint: %+v", h)
	}
	fc := db.GeoJSON()
	if n := len(fc["features"].([]any)); n != 3 {
		t.Fatalf("geojson features %d", n)
	}
	props := fc["features"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if props["stations"] != "New York, NY, United States; Bude, United Kingdom" || props["rfs"] != "2001" {
		t.Fatalf("props: %+v", props)
	}
	lfc := db.LandingGeoJSON()
	if n := len(lfc["features"].([]any)); n != 4 {
		t.Fatal("landing geojson")
	}
}

func TestBuildPeeringDB(t *testing.T) {
	fac := `{"data":[{"id":1,"name":"Equinix FR5","city":"Frankfurt","country":"DE","latitude":50.1,"longitude":8.7},
{"id":2,"name":"Interxion FRA","city":"Frankfurt","country":"DE","latitude":50.12,"longitude":8.74},
{"id":3,"name":"Remote","city":"Berlin","country":"DE","latitude":52.5,"longitude":13.4},
{"id":4,"name":"No coords","city":"X","country":"DE","latitude":null,"longitude":null}]}`
	ix := `{"data":[{"id":31,"name":"DE-CIX Frankfurt","city":"Frankfurt","country":"DE"},{"id":32,"name":"Lonely IX","city":"Nowhere","country":"DE"}]}`
	ixfac := `{"data":[{"ix_id":31,"fac_id":1},{"ix_id":31,"fac_id":2},{"ix_id":31,"fac_id":3},{"ix_id":32,"fac_id":4}]}`
	net := `{"data":[{"id":4224,"asn":13335,"name":"Cloudflare","info_type":"Content","info_ratio":"Mostly Outbound","policy_general":"Open","ix_count":2,"fac_count":1}]}`
	netixlan := `{"data":[{"net_id":4224,"asn":13335,"ix_id":31,"speed":100000,"ipaddr4":"80.81.192.1","ipaddr6":null,"is_rs_peer":true,"operational":true}]}`
	netfac := `{"data":[{"net_id":4224,"fac_id":1,"local_asn":13335}]}`
	db, err := BuildPeeringDB([]byte(fac), []byte(ix), []byte(ixfac), []byte(net), []byte(netixlan), []byte(netfac))
	if err != nil {
		t.Fatal(err)
	}
	d := db.IX[31]
	if d.Lat < 50.09 || d.Lat > 50.13 || d.Lon < 8.69 || d.Lon > 8.75 { // Berlin excluded: not in the IX city
		t.Fatalf("ix centroid %+v", d)
	}
	if db.IX[32].Located() || db.Fac[4].Located() {
		t.Fatal("unlocated places got coordinates")
	}
	n := db.Nets[13335]
	if n == nil || n.Type != "Content" || len(n.Ports) != 1 || n.Ports[0].IPv4 != "80.81.192.1" || !n.Ports[0].RSPeer || len(n.Facs) != 1 {
		t.Fatalf("nets: %+v", n)
	}
}

// TestUpdateFallback: a feed that fails to refresh keeps serving the old copy,
// a 304 counts as fresh, bad payloads never replace good data.
func TestUpdateFallback(t *testing.T) {
	dir := t.TempDir()
	cache.SetDir(dir)
	defer cache.SetDir("")
	var mode atomic.Int32
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch mode.Load() {
		case 0:
			w.Header().Set("ETag", `"v1"`)
			w.Write([]byte("1.2.3.4\n5.6.7.0/24\n"))
		case 1:
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(304)
				return
			}
			w.Write([]byte("9.9.9.9\n"))
		case 2:
			w.WriteHeader(500)
		case 3:
			w.Write([]byte("<html>not a list</html>"))
		}
	}))
	defer srv.Close()
	f := &Feed{Name: "test-netset", URL: srv.URL, Kind: KindNetset, Type: "t", TTL: time.Hour, Rep: true}
	All = append(All, f)
	defer func() { All = All[:len(All)-1] }()
	ctx := context.Background()

	if r := Update(ctx, f); !r.Updated || r.Entries != 2 {
		t.Fatalf("first update: %+v", r)
	}
	mode.Store(1)
	if r := Update(ctx, f); !r.Unchanged {
		t.Fatalf("304 not honoured: %+v", r)
	}
	mode.Store(2)
	if r := Update(ctx, f); r.Err == nil {
		t.Fatal("500 should fail")
	}
	mode.Store(3)
	if r := Update(ctx, f); r.Err == nil || !strings.Contains(r.Error, "bad payload") {
		t.Fatalf("garbage accepted: %+v", r)
	}
	s, note := NetSet(ctx, "test-netset")
	if s == nil || !s.Contains(netip.MustParseAddr("5.6.7.8")) {
		t.Fatal("old copy lost")
	}
	if note != "" {
		t.Fatalf("fresh copy has a note: %q", note)
	}
	// make it stale: the refresh fails, the old copy still answers with a note
	m := readMeta(f)
	m.Checked = time.Now().Add(-2 * time.Hour)
	m.Fetched = m.Checked
	m.ErrorAt = time.Time{}
	writeMeta(f, m)
	invalidate(f.Name)
	mode.Store(2)
	s, note = NetSet(ctx, "test-netset")
	if s == nil || s.Len() != 2 || !strings.Contains(note, "old") {
		t.Fatalf("stale fallback: %v %q", s, note)
	}
	if _, err := os.Stat(dataPath(f)); err != nil {
		t.Fatal(err)
	}
	st := Stat()
	found := false
	for _, x := range st {
		if x.Name == "test-netset" {
			found = true
			if x.Fresh || x.Error == "" || x.Entries != 2 {
				t.Fatalf("status: %+v", x)
			}
		}
	}
	if !found {
		t.Fatal("status missing")
	}
}

func TestPeeringDumpTables(t *testing.T) {
	dump := `{"api":{"x":1},"fac":{"data":[{"id":1,"name":"F","city":"C","country":"DE","latitude":1,"longitude":2}],"meta":{}},
"ix":{"data":[{"id":2,"name":"IX","city":"C","country":"DE"}]},"ixfac":{"data":[{"ix_id":2,"fac_id":1}]},"poc":{"data":[{"huge":"skip"}]},
"net":{"data":[{"id":3,"asn":64500,"name":"N","info_type":"NSP"}]},"netixlan":{"data":[{"net_id":3,"ix_id":2,"speed":1000}]},
"netfac":{"data":[{"net_id":3,"fac_id":1}]}}`
	tb, err := PeeringDumpTables(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tb["poc"]; ok {
		t.Fatal("unwanted table kept")
	}
	db, err := BuildPeeringDB(tb["fac"], tb["ix"], tb["ixfac"], tb["net"], tb["netixlan"], tb["netfac"])
	if err != nil || db.Nets[64500] == nil || db.Nets[64500].Ports[0].Speed != 1000 || db.IX[2].Lat != 1 {
		t.Fatalf("%v %+v", err, db)
	}
	if _, err := PeeringDumpTables(strings.NewReader(`{"fac":{"data":[]}}`)); err == nil {
		t.Fatal("missing tables accepted")
	}
}
