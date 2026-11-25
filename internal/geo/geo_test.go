package geo

import (
	"math"
	"net"
	"strings"
	"testing"

	"github.com/PalMeany/traced-cli/internal/trace"
)

func TestParseHostname(t *testing.T) {
	cases := map[string]string{
		"be3271.ccr41.fra03.atlas.cogentco.com":            "Frankfurt",
		"ae-5.r24.frnkge13.de.bb.gin.ntt.net":              "Frankfurt",
		"ae-1-51.ear1.Frankfurt1.Level3.net":               "Frankfurt",
		"ffm-bb2-link.ip.twelve99.net":                     "Frankfurt",
		"sto-b2-link.ip.twelve99.net":                      "Stockholm",
		"fra16s52-in-f14.1e100.net":                        "Frankfurt",
		"mag9-cr03-be12.51.msk.mts-internet.net":           "Moscow",
		"core1.ams1.he.net":                                "Amsterdam",
		"ae2.cr0-waw1.ip4.gtt.net":                         "Warsaw",
		"xe-0-0-1.RT.M9.MSK.RU.retn.net":                   "Moscow",
		"ae-12.r21.asbnva02.us.bb.gin.ntt.net":             "Ashburn",
		"spb-ix.selectel.ru":                               "St Petersburg",
		"ec2-3-120-1-1.eu-central-1.compute.amazonaws.com": "Frankfurt",
		"lag-1.ear3.London2.Level3.net":                    "London",
		"hel-b2-link.ip.twelve99.net":                      "Helsinki",
	}
	for h, want := range cases {
		m := ParseHostname(h)
		if m == nil || m.City == nil || m.City.Name != want {
			got := "<nil>"
			if m != nil && m.City != nil {
				got = m.City.Name + " via " + m.Token
			}
			t.Errorf("%s: want %s, got %s", h, want, got)
		}
	}
	if m := ParseHostname("be3271.ccr41.fra03.atlas.cogentco.com"); m.Backbone == nil || m.Backbone.ASN != 174 {
		t.Errorf("cogent backbone not detected")
	}
	for _, h := range []string{"acc-sw1.example.net", "static.12.34.example.com", "router.local", "tun0.vpn.example.org"} {
		if m := ParseHostname(h); m != nil && m.City != nil && m.Confidence >= 0.6 {
			t.Errorf("%s: false positive %s (%.2f)", h, m.City.Name, m.Confidence)
		}
	}
}

func TestCityTable(t *testing.T) {
	if CityCount() < 200 {
		t.Fatalf("only %d cities", CityCount())
	}
	for _, c := range []string{"msk", "spb", "fra", "ams", "waw", "sto", "hel", "lon", "par", "mad", "vie", "zrh", "prg",
		"sin", "hkg", "nrt", "iad", "jfk", "lax", "sjc", "ord", "dfw", "sea", "mia", "atl"} {
		if LookupCity(c) == nil {
			t.Errorf("missing %s", c)
		}
	}
	if c := LookupCityIn("Frankfurt am Main", "DE"); c == nil || c.Code != "fra" {
		t.Errorf("name lookup failed: %+v", c)
	}
}

func TestIXP(t *testing.T) {
	for ip, want := range map[string]string{"195.208.209.10": "MSK-IX", "80.81.192.5": "DE-CIX Frankfurt", "80.249.208.1": "AMS-IX", "195.66.224.10": "LINX"} {
		x := LookupIXP(net.ParseIP(ip))
		if x == nil || !strings.Contains(x.Name, want) {
			t.Errorf("%s: want %s, got %+v", ip, want, x)
		}
	}
	if LookupIXP(net.ParseIP("8.8.8.8")) != nil {
		t.Error("8.8.8.8 is not an IXP")
	}
}

const feed = `# RFC 8805 sample
192.0.2.0/24,US,US-CA,San Jose,95112
192.0.2.128/25,DE,DE-HE,Frankfurt,
2001:db8::/32,NL,,Amsterdam,
198.51.100.7,RU,RU-MOW,Moscow
garbage line
`

func TestGeofeed(t *testing.T) {
	e, err := ParseGeofeed(strings.NewReader(feed))
	if err != nil || len(e) != 4 {
		t.Fatalf("parse: %v %d", err, len(e))
	}
	g := &Geofeed{Entries: e}
	if m := g.Lookup(net.ParseIP("192.0.2.200")); m == nil || m.City != "Frankfurt" {
		t.Errorf("longest prefix: %+v", m)
	}
	if m := g.Lookup(net.ParseIP("192.0.2.5")); m == nil || m.City != "San Jose" || m.Region != "US-CA" {
		t.Errorf("/24: %+v", m)
	}
	if m := g.Lookup(net.ParseIP("2001:db8::1")); m == nil || m.Country != "NL" {
		t.Errorf("v6: %+v", m)
	}
	if m := g.Lookup(net.ParseIP("198.51.100.7")); m == nil || m.City != "Moscow" {
		t.Errorf("bare ip: %+v", m)
	}
	if g.Lookup(net.ParseIP("203.0.113.1")) != nil {
		t.Error("unexpected match")
	}
	c := feedCandidate(g.Lookup(net.ParseIP("192.0.2.200")), "x", 0.85)
	if !c.HasCoords || c.Source != SrcGeofeed {
		t.Errorf("geofeed candidate without coords: %+v", c)
	}
}

func TestExtractGeofeedURL(t *testing.T) {
	ripe := `{"remarks":[{"description":["Geofeed https://example.net/geofeed.csv"]}]}`
	if u := ExtractGeofeedURL(ripe); u != "https://example.net/geofeed.csv" {
		t.Errorf("remark: %q", u)
	}
	attr := "inetnum: 192.0.2.0 - 192.0.2.255\ngeofeed:        https://isp.example/feed.csv\n"
	if u := ExtractGeofeedURL(attr); u != "https://isp.example/feed.csv" {
		t.Errorf("attr: %q", u)
	}
	link := `{"links":[{"value":"x","rel":"geofeed","href":"https://geo.example/a.csv","type":"text/csv"}]}`
	if u := ExtractGeofeedURL(link); u != "https://geo.example/a.csv" {
		t.Errorf("link: %q", u)
	}
	if u := ExtractGeofeedURL(`{"name":"NET"}`); u != "" {
		t.Errorf("false positive %q", u)
	}
}

func TestPhysics(t *testing.T) {
	msk, fra := LookupCity("msk"), LookupCity("fra")
	d := DistanceKm(msk.Lat, msk.Lon, fra.Lat, fra.Lon)
	if math.Abs(d-2020) > 60 {
		t.Fatalf("Moscow–Frankfurt %.0f km", d)
	}
	if r := MinRTTms(1000); r != 10 {
		t.Fatalf("1000 km -> %.1f ms, want 10", r)
	}
	a := Point{Lat: msk.Lat, Lon: msk.Lon, RTT: 2}
	if ok, _ := Feasible(a, Point{Lat: fra.Lat, Lon: fra.Lon, RTT: 5}); ok {
		t.Error("Frankfurt at 5 ms from Moscow must be impossible")
	}
	if ok, _ := Feasible(a, Point{Lat: fra.Lat, Lon: fra.Lon, RTT: 40}); !ok {
		t.Error("Frankfurt at 40 ms must be possible")
	}
}

func TestValidateRejectsTeleport(t *testing.T) {
	msk := LookupCity("msk")
	hops := []trace.Hop{
		{TTL: 1, Responders: []trace.Responder{{IP: "212.188.6.44", RTTs: []float64{2}}}},
		{TTL: 2, Responders: []trace.Responder{{IP: "203.0.113.9", RTTs: []float64{5}}}},
	}
	data := map[string]*IPData{
		"212.188.6.44": {cands: []Candidate{{Source: SrcRDNS, City: "Moscow", Country: "RU", Lat: msk.Lat, Lon: msk.Lon, HasCoords: true, Confidence: 0.8}}},
		"203.0.113.9": {cands: []Candidate{
			{Source: SrcGeoIP, City: "Ashburn", Country: "US", Lat: 39.04, Lon: -77.49, HasCoords: true, Confidence: 0.9},
			{Source: SrcIPMap, City: "Moscow", Country: "RU", Lat: 55.75, Lon: 37.6, HasCoords: true, Confidence: 0.7},
		}},
	}
	Validate(hops, data, nil)
	info := hops[1].Responders[0].Geo.(*Info)
	if !info.RTTAnomaly || info.Source != SrcIPMap || info.City != "Moscow" {
		t.Fatalf("expected anomaly + switch to ipmap, got %+v", info)
	}
	// nothing plausible -> interpolate from the previous hop
	data["203.0.113.9"].cands = data["203.0.113.9"].cands[:1]
	Validate(hops, data, nil)
	info = hops[1].Responders[0].Geo.(*Info)
	if info.Source != SrcInterp || info.City != "Moscow" {
		t.Fatalf("expected interpolation, got %+v", info)
	}
	// with a known origin a single hop is checked too
	hops2 := hops[1:]
	data["203.0.113.9"].cands = []Candidate{{Source: SrcGeoIP, City: "Ashburn", Country: "US", Lat: 39.04, Lon: -77.49, HasCoords: true, Confidence: 0.9}}
	Validate(hops2, data, &Point{Lat: msk.Lat, Lon: msk.Lon})
	if info := hops2[0].Responders[0].Geo.(*Info); !info.RTTAnomaly {
		t.Fatalf("origin check missed: %+v", info)
	}
}

func TestPrivate(t *testing.T) {
	for _, s := range []string{"192.168.1.1", "10.1.2.3", "100.69.0.1", "fd00::1", "fe80::1"} {
		if !IsPrivate(net.ParseIP(s)) {
			t.Errorf("%s should be private", s)
		}
	}
	if IsPrivate(net.ParseIP("1.1.1.1")) {
		t.Error("1.1.1.1 is public")
	}
}
