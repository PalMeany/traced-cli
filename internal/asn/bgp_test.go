package asn

import "testing"

func TestParseLookingGlass(t *testing.T) {
	raw := []byte(`{
		"data": {
			"rrcs": [
				{
					"rrc": "RRC00",
					"peers": [
						{"asn_origin": "13335", "as_path": "3356 1299 13335 13335"},
						{"asn_origin": "13335", "as_path": "174 1299 13335"},
						{"asn_origin": "13335", "as_path": "2914 3356 13335"}
					]
				},
				{
					"rrc": "RRC01",
					"peers": [
						{"asn_origin": "13335", "as_path": "6939 1299 13335"}
					]
				}
			]
		}
	}`)
	orig, ups, peers, err := ParseLookingGlass(raw)
	if err != nil {
		t.Fatal(err)
	}
	if orig != 13335 || peers != 4 {
		t.Fatalf("got orig=%d peers=%d, want 13335 / 4", orig, peers)
	}
	if len(ups) != 2 {
		t.Fatalf("got %d upstreams, want 2: %+v", len(ups), ups)
	}
	if ups[0].ASN != 1299 || ups[0].Peers != 3 || ups[0].Pct != 75 {
		t.Fatalf("top upstream = %+v, want AS1299 3 peers 75%%", ups[0])
	}
	if ups[1].ASN != 3356 || ups[1].Peers != 1 || ups[1].Pct != 25 {
		t.Fatalf("second upstream = %+v, want AS3356 1 peer 25%%", ups[1])
	}
}

func TestParseBGPViewPrefix(t *testing.T) {
	raw := []byte(`{
		"status": "ok",
		"data": {
			"asns": [{
				"asn": 13335,
				"name": "CLOUDFLARENET",
				"prefix_upstreams": [
					{"asn": 1299, "name": "TWELVE99"},
					{"asn": 3356, "name": "LEVEL3"}
				]
			}]
		}
	}`)
	orig, name, ups, err := ParseBGPViewPrefix(raw)
	if err != nil {
		t.Fatal(err)
	}
	if orig != 13335 || name != "CLOUDFLARENET" || len(ups) != 2 {
		t.Fatalf("unexpected result: orig=%d name=%q ups=%+v", orig, name, ups)
	}
}

func TestParsePrefixHistory(t *testing.T) {
	raw := []byte(`{
		"data": {
			"query_endtime": "2026-11-26T00:00:00",
			"by_origin": [
				{
					"origin": "64500",
					"prefixes": [{"prefix": "198.51.100.0/24", "timelines": [{"starttime": "2024-12-01T00:00:00", "endtime": "2025-06-01T00:00:00"}]}]
				},
				{
					"origin": "13335",
					"prefixes": [{"prefix": "198.51.100.0/24", "timelines": [{"starttime": "2025-06-02T00:00:00", "endtime": "2026-11-26T00:00:00"}]}]
				}
			]
		}
	}`)
	evs, changes, err := ParsePrefixHistory(raw)
	if err != nil {
		t.Fatal(err)
	}
	if changes != 1 || len(evs) != 2 {
		t.Fatalf("got changes=%d evs=%+v", changes, evs)
	}
	if evs[0].ASN != 64500 || evs[0].Active {
		t.Fatalf("first event should be inactive AS64500: %+v", evs[0])
	}
	if evs[1].ASN != 13335 || !evs[1].Active {
		t.Fatalf("second event should be active AS13335: %+v", evs[1])
	}
}

func TestParseASNHistory(t *testing.T) {
	raw := []byte(`{
		"data": {
			"by_origin": [{
				"origin": "13335",
				"prefixes": [
					{"prefix": "1.1.1.0/24", "timelines": [{"starttime": "2025-01-01T00:00:00", "endtime": "2026-11-26T00:00:00"}]},
					{"prefix": "1.0.0.0/24", "timelines": [{"starttime": "2025-06-01T00:00:00", "endtime": "2026-11-26T00:00:00"}]}
				]
			}]
		}
	}`)
	h, err := ParseASNHistory(raw)
	if err != nil || h == nil {
		t.Fatalf("ParseASNHistory failed: %v %+v", err, h)
	}
	if h.FirstSeen != "2025-01-01" || h.LastSeen != "2026-11-26" || h.Peak != 2 || h.Current != 2 {
		t.Fatalf("unexpected history: %+v", h)
	}
}
