package geo

import (
	"testing"

	"github.com/PalMeany/traced-cli/internal/trace"
)

func TestSourcePriorityAndDiscrepancies(t *testing.T) {
	if !(SourcePriority(SrcIXP) < SourcePriority(SrcGeofeed) &&
		SourcePriority(SrcGeofeed) < SourcePriority(SrcRDNS) &&
		SourcePriority(SrcRDNS) < SourcePriority(SrcIPMap) &&
		SourcePriority(SrcIPMap) < SourcePriority(SrcGeoIP)) {
		t.Fatalf("unexpected source priority ordering")
	}

	hops := []trace.Hop{{TTL: 1, Responders: []trace.Responder{{IP: "198.51.100.1", RTTs: []float64{25}}}}}
	data := map[string]*IPData{
		"198.51.100.1": {
			cands: []Candidate{
				{Source: SrcGeofeed, Priority: SourcePriority(SrcGeofeed), City: "Frankfurt", Country: "DE", Lat: 50.11, Lon: 8.68, HasCoords: true, Confidence: 0.85, Detail: "rfc8805"},
				{Source: SrcIPMap, Priority: SourcePriority(SrcIPMap), City: "Frankfurt", Country: "DE", Lat: 50.12, Lon: 8.69, HasCoords: true, Confidence: 0.7, Detail: "score 30"},
				{Source: SrcGeoIP, Priority: SourcePriority(SrcGeoIP), City: "New York", Country: "US", Lat: 40.71, Lon: -74.00, HasCoords: true, Confidence: 0.45, Detail: "ip-api.com"},
			},
		},
	}
	Validate(hops, data, nil)
	info, ok := hops[0].Responders[0].Geo.(*Info)
	if !ok || info == nil {
		t.Fatal("missing geo info")
	}
	if info.Source != SrcGeofeed || info.Priority != SourcePriority(SrcGeofeed) {
		t.Fatalf("got source=%s prio=%d, want geofeed/%d", info.Source, info.Priority, SourcePriority(SrcGeofeed))
	}
	if len(info.Discrepancies) != 1 {
		t.Fatalf("expected 1 discrepancy (NY vs Frankfurt), got %+v", info.Discrepancies)
	}
	if !info.Candidates[0].Chosen {
		t.Fatalf("chosen flag not set on primary candidate")
	}
}

func TestLookupIXPByHostname(t *testing.T) {
	if x := LookupIXPByHostname("et-0-0-0.de-cix.net"); x == nil || x.Name != "DE-CIX" || x.Via != "rdns" {
		t.Fatalf("expected DE-CIX via rdns, got %+v", x)
	}
	if x := LookupIXPByHostname("peer.msk-ix.ru"); x == nil || x.Name != "MSK-IX" {
		t.Fatalf("expected MSK-IX, got %+v", x)
	}
	if x := LookupIXPByHostname("example.com"); x != nil {
		t.Fatalf("expected nil for example.com, got %+v", x)
	}
}
