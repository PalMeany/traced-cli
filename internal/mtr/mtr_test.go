package mtr

import (
	"math"
	"testing"

	"github.com/PalMeany/traced-cli/internal/trace"
)

func TestHopStats(t *testing.T) {
	h := newHop(3)
	for _, v := range []float64{10, 12, 14} {
		h.Add(trace.Probe{IP: "1.1.1.1", RTT: v})
	}
	h.Add(trace.Probe{Lost: true})
	h.Add(trace.Probe{IP: "1.1.1.2", RTT: 20})
	if h.Sent != 5 || h.Recv != 4 || h.Loss() != 20 {
		t.Fatalf("sent %d recv %d loss %v", h.Sent, h.Recv, h.Loss())
	}
	if h.Best != 10 || h.Worst != 20 || h.Last != 20 || math.Abs(h.Avg()-14) > 1e-9 {
		t.Fatalf("best %v worst %v avg %v", h.Best, h.Worst, h.Avg())
	}
	if math.Abs(h.StDev()-4.3205) > 1e-3 {
		t.Fatalf("stdev %v", h.StDev())
	}
	if h.Primary() != "1.1.1.1" || len(h.IPs) != 2 {
		t.Fatalf("primary %s", h.Primary())
	}
	if s := Spark([]float64{1, -1, 8}, 5); len([]rune(s)) < 5 {
		t.Fatalf("spark %q", s)
	}
}
