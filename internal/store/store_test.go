package store

import (
	"testing"
	"time"

	"github.com/PalMeany/traced-cli/internal/trace"
)

type asn struct {
	ASN int `json:"asn"`
}

func hop(ttl int, ip string, as int, rtt float64) trace.Hop {
	h := trace.Aggregate(ttl, []trace.Probe{{TTL: ttl, IP: ip, RTT: rtt}, {TTL: ttl, IP: ip, RTT: rtt}})
	if as != 0 {
		h.Responders[0].Network = asn{as}
	}
	return h
}

func TestDiff(t *testing.T) {
	a := &trace.Result{ID: "a", Target: "x", Hops: []trace.Hop{hop(1, "10.0.0.1", 0, 1), hop(2, "2.2.2.2", 100, 5), hop(3, "3.3.3.3", 200, 10)}}
	b := &trace.Result{ID: "b", Target: "x", Hops: []trace.Hop{hop(1, "10.0.0.1", 0, 1), hop(2, "4.4.4.4", 300, 8), hop(3, "3.3.3.3", 200, 25), hop(4, "5.5.5.5", 200, 26)}}
	// ECMP branch on hop 3 of b
	b.Hops[2] = trace.Aggregate(3, []trace.Probe{{IP: "3.3.3.3", RTT: 25}, {IP: "3.3.3.4", RTT: 25}})
	b.Hops[2].Responders[0].Network = asn{200}
	d := Compare(a, b)
	st := map[int]string{}
	for _, h := range d.Hops {
		st[h.TTL] = h.Status
	}
	if st[1] != "same" || st[2] != "changed" || st[3] != "ecmp" || st[4] != "added" {
		t.Fatalf("statuses %v", st)
	}
	if !d.ASPathChanged || FormatASPath(d.ASPathA) != "AS100 → AS200" || FormatASPath(d.ASPathB) != "AS300 → AS200" {
		t.Fatalf("as path %v %v", d.ASPathA, d.ASPathB)
	}
	if d.FinalDelta != 16 || d.Changed != 2 {
		t.Fatalf("delta %v changed %d", d.FinalDelta, d.Changed)
	}
	if d.Hops[1].Delta != 3 {
		t.Fatalf("hop delta %v", d.Hops[1].Delta)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	t0 := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		r := &trace.Result{Target: "host", Started: t0.Add(time.Duration(i) * time.Minute), Hops: []trace.Hop{hop(1, "1.1.1.1", 13335, 9)}, Reached: true}
		if err := s.Save(r); err != nil {
			t.Fatal(err)
		}
	}
	l := s.List(0)
	if len(l) != 3 || !l[0].Started.After(l[1].Started) {
		t.Fatalf("list %+v", l)
	}
	r, err := s.Load("1")
	if err != nil || r.ID != l[0].ID {
		t.Fatalf("load newest: %v %v", err, r)
	}
	if _, err := s.Load(l[2].ID[:13] + "x"); err == nil {
		t.Fatal("bogus ref resolved")
	}
	if r, err := s.Load(l[1].ID); err != nil || ASNOf(r.Hops[0].Primary()) != 13335 {
		t.Fatalf("decoded asn: %v", err)
	}
}
