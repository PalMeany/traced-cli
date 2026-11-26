package asn

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/feeds"
)

const pdbSample = `{"data":[{"id":4224,"name":"Cloudflare","aka":"","website":"https://www.cloudflare.com","asn":13335,
"irr_as_set":"ARIN::AS13335:AS-CLOUDFLARE","info_type":"Content","info_traffic":"","info_ratio":"Mostly Outbound","info_scope":"Global",
"info_prefixes4":80000,"info_prefixes6":30000,"policy_general":"Open","policy_url":"https://www.cloudflare.com/peering-policy/",
"policy_locations":"Preferred","policy_contracts":"Not Required","ix_count":2,"fac_count":2,"updated":"2026-11-23T13:52:23Z",
"netfac_set":[{"fac_id":1,"name":"Equinix DC1","city":"Ashburn","country":"US"},{"fac_id":1,"name":"Equinix DC1","city":"Ashburn","country":"US"},{"fac_id":2,"name":"DRT SFO","city":"San Francisco","country":"US"}],
"netixlan_set":[{"ix_id":255,"name":"Equinix Paris: Equinix IX - PA Metro","speed":100000,"ipaddr4":"195.42.144.143","ipaddr6":"2001:7f8:43::1:3335:1","is_rs_peer":false,"operational":true},
{"ix_id":255,"name":"Equinix Paris: Equinix IX - PA Metro","speed":100000,"ipaddr4":"195.42.144.144","ipaddr6":null,"is_rs_peer":true,"operational":true},
{"ix_id":26,"name":"AMS-IX","speed":400000,"ipaddr4":"80.249.211.140","is_rs_peer":false,"operational":true}]}]}`

func TestParsePeeringDBNet(t *testing.T) {
	places := &feeds.PeeringDB{Fac: map[int]*feeds.Place{1: {ID: 1, Lat: 39.01, Lon: -77.45}},
		IX: map[int]*feeds.Place{255: {ID: 255, Name: "Equinix Paris", City: "Paris", Country: "FR", Lat: 48.9, Lon: 2.3}}}
	p, err := ParsePeeringDBNet([]byte(pdbSample), places)
	if err != nil || p == nil {
		t.Fatal(err)
	}
	if p.Type != "Content" || p.Ratio != "Mostly Outbound" || p.Policy != "Open" || p.Prefixes4 != 80000 {
		t.Fatalf("fields: %+v", p)
	}
	if len(p.IXs) != 2 || p.IXs[0].ID != 26 || p.IXs[1].Ports != 2 || p.IXs[1].SpeedMb != 200000 || !p.IXs[1].RSPeer {
		t.Fatalf("ixs: %+v", p.IXs)
	}
	if p.IXs[1].City != "Paris" || p.IXs[1].Lat != 48.9 || p.IXs[0].Lat != 0 {
		t.Fatalf("ix placement: %+v", p.IXs)
	}
	if len(p.Facilities) != 2 || p.Facilities[0].Lat != 39.01 || p.Facilities[1].Lat != 0 {
		t.Fatalf("facilities: %+v", p.Facilities)
	}
	if p, err := ParsePeeringDBNet([]byte(`{"data":[]}`), nil); p != nil || err != nil {
		t.Fatal("empty data should be nil, nil")
	}
	b := BriefOf(&Report{ASN: 13335, Name: "Cloudflare", PeeringDB: p}, [][2]float64{{48.85, 2.35}}, 10)
	if len(b.PoPs) != 2 || b.PoPs[0].Kind != "ix" || b.PoPs[0].City != "Paris" {
		t.Fatalf("brief pops sorted by distance: %+v", b.PoPs)
	}
}

const caidaSample = `{"data":{"asn":{"asn":"13335","asnName":"CLOUDFLARENET","rank":61,"organization":{"orgName":"Cloudflare, Inc.","orgId":"e62eae750a"},
"country":{"iso":"US","name":"United States"},"cliqueMember":true,"seen":true,"longitude":-106.6,"latitude":54.6,
"cone":{"numberAsns":1064,"numberPrefixes":44598,"numberAddresses":50474136},
"asnDegree":{"provider":98,"peer":393,"customer":1063,"total":1554,"transit":1383,"sibling":5}}}}`

func TestParseCAIDA(t *testing.T) {
	r, err := ParseCAIDA([]byte(caidaSample))
	if err != nil {
		t.Fatal(err)
	}
	if r.Rank != 61 || r.ConeASNs != 1064 || r.ConeAddresses != 50474136 || r.Providers != 98 || r.Customers != 1063 || r.Org != "Cloudflare, Inc." || r.Clique {
		t.Fatalf("%+v", r)
	}
	t1 := strings.Replace(caidaSample, `"provider":98`, `"provider":0`, 1)
	if r, _ := ParseCAIDA([]byte(t1)); !r.Clique {
		t.Fatal("transit-free clique member not flagged")
	}
	if r, err := ParseCAIDA([]byte(`{"data":{"asn":null}}`)); r != nil || err != nil {
		t.Fatal("unknown asn")
	}
	if _, err := ParseCAIDA([]byte(`{"data":{"asn":null},"errors":[{"message":"bad"}]}`)); err == nil {
		t.Fatal("graphql error lost")
	}
}

func TestRIPEParsers(t *testing.T) {
	ap := `{"data":{"prefixes":[{"prefix":"104.16.0.0/13"},{"prefix":"104.16.0.0/20"},{"prefix":"1.1.1.0/24"},{"prefix":"2606:4700::/32"},{"prefix":"junk"}],
"query_starttime":"2026-11-12T00:00:00","query_endtime":"2026-11-26T00:00:00"}}`
	v4, v6, win, err := ParseAnnounced([]byte(ap))
	if err != nil || len(v4) != 3 || len(v6) != 1 || v4[0] != "1.1.1.0/24" || win != "2026-11-12 … 2026-11-26" {
		t.Fatalf("%v %v %v %q", err, v4, v6, win)
	}
	if n := AddressCount(v4); n != 256+(1<<19) { // the /20 inside the /13 is not counted twice
		t.Fatalf("address count %d", n)
	}
	nb := `{"data":{"neighbour_counts":{"left":3,"right":1,"unique":4,"uncertain":0},"neighbours":[
{"asn":1031,"type":"left","power":2},{"asn":1299,"type":"left","power":6769},{"asn":64500,"type":"right","power":9},{"asn":174,"type":"left","power":5509}]}}`
	l, r, u, ups, err := ParseNeighbours([]byte(nb), 2)
	if err != nil || l != 3 || r != 1 || u != 0 || len(ups) != 2 || ups[0].ASN != 1299 || ups[1].ASN != 174 {
		t.Fatalf("%v %d %d %+v", err, l, r, ups)
	}
	for in, want := range map[string]int{"AS13335": 13335, "as1": 1, "13335": 13335, "ASN 7": 0, "ASN7": 7, "x": 0, "AS0": 0} {
		if n, _ := ParseASN(in); n != want {
			t.Errorf("ParseASN(%q)=%d want %d", in, n, want)
		}
	}
}

// TestProfileDegrades: a 429 from one source and a hanging source leave the
// rest of the profile intact and are reported per source.
func TestProfileDegrades(t *testing.T) {
	cache.SetDir(t.TempDir())
	defer cache.SetDir("")
	feeds.AutoUpdate = false
	defer func() { feeds.AutoUpdate = true }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/pdb/"):
			w.WriteHeader(429)
		case strings.HasPrefix(r.URL.Path, "/caida"):
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"asn":"13335"`) {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, caidaSample)
		case strings.Contains(r.URL.Path, "announced-prefixes"):
			io.WriteString(w, `{"data":{"prefixes":[{"prefix":"1.1.1.0/24"},{"prefix":"2606:4700::/32"}]}}`)
		case strings.Contains(r.URL.Path, "as-overview"):
			io.WriteString(w, `{"data":{"holder":"CLOUDFLARENET - Cloudflare, Inc."}}`)
		case strings.Contains(r.URL.Path, "routing-status"):
			select { // hangs past the source timeout
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		case strings.Contains(r.URL.Path, "asn-neighbours"):
			io.WriteString(w, `{"data":{"neighbour_counts":{"left":1,"right":0,"uncertain":0},"neighbours":[{"asn":174,"type":"left","power":5}]}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	PeeringDBURL, CAIDAURL, RIPEstatURL = srv.URL+"/pdb", srv.URL+"/caida", srv.URL+"/ripe"
	defer func() {
		PeeringDBURL, CAIDAURL, RIPEstatURL = "https://www.peeringdb.com/api", "https://api.asrank.caida.org/v2/graphql", "https://stat.ripe.net/data"
	}()
	o := Full
	o.Timeout = 700 * time.Millisecond
	r := Profile(context.Background(), 13335, o)
	src := map[string]Source{}
	for _, s := range r.Sources {
		src[s.Name] = s
	}
	if !strings.Contains(src["peeringdb"].Error, "429") || src["peeringdb"].OK {
		t.Fatalf("peeringdb: %+v", src["peeringdb"])
	}
	if !src["caida"].OK || r.Rank == nil || r.Rank.Rank != 61 {
		t.Fatalf("caida: %+v %+v", src["caida"], r.Rank)
	}
	rs := src["ripestat"]
	if !rs.OK || !strings.Contains(rs.Error, "routing-status") || r.Routing == nil || r.Routing.CountV4 != 1 || r.Routing.Left != 1 {
		t.Fatalf("ripestat partial: %+v %+v", rs, r.Routing)
	}
	if src["apnic"].OK { // feed not downloaded, auto-update off
		t.Fatalf("apnic should fail without feed: %+v", src["apnic"])
	}
	if r.Name == "" || r.Country != "US" {
		t.Fatalf("name/country: %q %q", r.Name, r.Country)
	}
	// second run is served from cache for CAIDA/RIPE
	r2 := Profile(context.Background(), 13335, o)
	for _, s := range r2.Sources {
		if s.Name == "caida" && !s.Cached {
			t.Fatal("caida not cached")
		}
	}
}

func TestFromBulk(t *testing.T) {
	db := &feeds.PeeringDB{
		Fac: map[int]*feeds.Place{1: {ID: 1, Name: "Equinix FR5", City: "Frankfurt", Country: "DE", Lat: 50.1, Lon: 8.7}},
		IX:  map[int]*feeds.Place{31: {ID: 31, Name: "DE-CIX Frankfurt", City: "Frankfurt", Country: "DE", Lat: 50.11, Lon: 8.72}},
		Nets: map[int]*feeds.NetRec{13335: {ID: 4224, Name: "Cloudflare", Type: "Content", Policy: "Open", IXCount: 1, FacCount: 1,
			Ports: []feeds.NetIXPort{{IX: 31, Speed: 100000, IPv4: "80.81.192.1"}, {IX: 31, Speed: 100000, RSPeer: true}}, Facs: []int{1, 1}}},
	}
	p := FromBulk(db, 13335)
	if p == nil || p.Name != "Cloudflare" || len(p.IXs) != 1 || p.IXs[0].SpeedMb != 200000 || p.IXs[0].Ports != 2 || !p.IXs[0].RSPeer ||
		p.IXs[0].Lat != 50.11 || len(p.Facilities) != 1 || p.Facilities[0].Name != "Equinix FR5" {
		t.Fatalf("%+v", p)
	}
	if FromBulk(db, 1) != nil || FromBulk(&feeds.PeeringDB{}, 13335) != nil {
		t.Fatal("missing should be nil")
	}
}
