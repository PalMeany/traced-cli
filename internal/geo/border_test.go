package geo

import (
	"os"
	"sort"
	"testing"

	"github.com/PalMeany/traced-cli/internal/trace"
)

func loadIPMap(t *testing.T, name string) Candidate {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseIPMap(b)
	if err != nil || c == nil {
		t.Fatalf("parse %s: %v %v", name, c, err)
	}
	return *c
}

// locate runs the same pipeline as Gather+Validate on prepared candidates.
func locate(cands []Candidate, rir string, rtt float64, prev ...Candidate) *Info {
	cands = Reconcile(cands, rir)
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Confidence > cands[j].Confidence })
	data := map[string]*IPData{"192.0.2.1": {cands: cands, rir: rir}}
	var hops []trace.Hop
	for i, p := range prev {
		ip := "198.51.100." + string(rune('1'+i))
		data[ip] = &IPData{cands: []Candidate{p}}
		hops = append(hops, trace.Hop{TTL: i + 1, Responders: []trace.Responder{{IP: ip, RTTs: []float64{rtt - 1}}}})
	}
	hops = append(hops, trace.Hop{TTL: len(hops) + 1, Responders: []trace.Responder{{IP: "192.0.2.1", RTTs: []float64{rtt}}}})
	Validate(hops, data, nil)
	return hops[len(hops)-1].Responders[0].Geo.(*Info)
}

// 45.66.160.1 (Creanova, Finland): IPmap only has a 655 km latency radius
// around a probe near Turku plus the "worlds" population pick -> Stockholm;
// ip-api says Los Angeles. Registry (RIPE) says FI.
func TestBorderCreanovaIsFinland(t *testing.T) {
	im := loadIPMap(t, "ipmap-45.66.160.1.json")
	if !im.Guess || im.Area == nil || im.Area.RadiusKm < 600 || im.Confidence > GuessConfidence {
		t.Fatalf("ipmap latency+worlds answer must be a low confidence guess with a radius: %+v", im)
	}
	geoip := Candidate{Source: SrcGeoIP, City: "Los Angeles", Country: "US", Lat: 33.87, Lon: -118.37, HasCoords: true, Confidence: 0.4}
	for _, prev := range [][]Candidate{nil, {{Source: SrcRDNS, City: "Helsinki", Country: "FI", Lat: 60.17, Lon: 24.94, HasCoords: true, Confidence: 0.8}}} {
		info := locate([]Candidate{im, geoip}, "FI", 31.8, prev...)
		if info.Country != "FI" || info.City != "Helsinki" || info.Source != SrcRIR {
			t.Fatalf("want Helsinki, FI via registry, got %s %s via %s (%+v)", info.City, info.Country, info.Source, info.Candidates)
		}
	}
	// without a registry country we keep IPmap's guess (no new claims invented),
	// but Los Angeles is still impossible: it is outside the latency radius
	geoip.Confidence = 0.5 // even when ranked above the guess
	info := locate([]Candidate{geoip, im}, "", 31.8)
	if info.Country != "SE" || info.Source != SrcIPMap {
		t.Fatalf("no registry: keep ipmap, got %+v", info)
	}
	for _, c := range info.Candidates {
		if c.Source == SrcGeoIP && c.Rejected != "" {
			return
		}
	}
	t.Fatalf("Los Angeles must be rejected by the latency radius: %+v", info.Candidates)
}

// 94.237.0.1 (UpCloud, registered FI) is a router in Copenhagen: IPmap has it
// from reverse DNS with a high score -> the registry must not override it.
func TestBorderMeasuredBeatsRegistry(t *testing.T) {
	im := loadIPMap(t, "ipmap-94.237.0.1.json")
	if im.Guess || im.Confidence < 0.6 {
		t.Fatalf("rdns-backed ipmap answer is not a guess: %+v", im)
	}
	info := locate([]Candidate{im, {Source: SrcGeoIP, City: "Helsinki", Country: "FI", Lat: 60.17, Lon: 24.94, HasCoords: true, Confidence: 0.4}}, "FI", 30)
	if info.City != "Copenhagen" || info.Source != SrcIPMap {
		t.Fatalf("want Copenhagen via ipmap, got %+v", info)
	}
}

// Synthetic border cases around the Gulf of Finland / Baltic.
func TestBorderReconcile(t *testing.T) {
	tallinn := Area{Lat: 59.44, Lon: 24.75, RadiusKm: 400}
	sto := LookupCity("sto")
	tll := LookupCity("tll")
	hel := LookupCity("hel")
	guess := func(c *City) Candidate {
		return Candidate{Source: SrcIPMap, City: c.Name, Country: c.Country, Lat: c.Lat, Lon: c.Lon, HasCoords: true,
			Confidence: GuessConfidence, Guess: true, Area: &tallinn}
	}
	cases := []struct {
		name  string
		cands []Candidate
		rir   string
		want  string
	}{
		// guess in registry country: untouched
		{"ee guess, ee registry", []Candidate{guess(tll)}, "EE", "Tallinn"},
		// guess Helsinki, registry EE: Tallinn is inside the radius -> Tallinn
		{"fi guess, ee registry", []Candidate{guess(hel)}, "EE", "Tallinn"},
		// guess Helsinki, registry NO: Oslo is far outside the radius -> keep Helsinki
		{"fi guess, no registry out of radius", []Candidate{guess(hel)}, "NO", "Helsinki"},
		// a geoip in the registry country inside the radius wins over the foreign guess
		{"geoip agrees with registry", []Candidate{guess(hel),
			{Source: SrcGeoIP, City: "Tallinn", Country: "EE", Lat: tll.Lat, Lon: tll.Lon, HasCoords: true, Confidence: 0.4}}, "EE", "Tallinn"},
		// strong rDNS is never demoted by the registry
		{"rdns vs registry", []Candidate{{Source: SrcRDNS, City: sto.Name, Country: "SE", Lat: sto.Lat, Lon: sto.Lon, HasCoords: true, Confidence: 0.8}}, "FI", "Stockholm"},
		// a strong claim outside a probe's radius survives (Cogent waw01 seen 4 ms from an Irish probe)
		{"rdns outside radius", []Candidate{guess(hel), {Source: SrcRDNS, City: "Warsaw", Country: "PL", Lat: 52.23, Lon: 21.01, HasCoords: true, Confidence: 0.88}}, "US", "Warsaw"},
		// registry "EU" carries no location
		{"eu registry", []Candidate{guess(hel)}, "EU", "Helsinki"},
	}
	for _, tc := range cases {
		info := locate(append([]Candidate(nil), tc.cands...), tc.rir, 12)
		if info.City != tc.want {
			t.Errorf("%s: want %s, got %s via %s", tc.name, tc.want, info.City, info.Source)
		}
	}
}
