package trace

import "testing"

func TestMTUSearch(t *testing.T) {
	cases := []struct {
		name      string
		min, max  int
		trueLimit int
		want      int
	}{
		{"full-1500", 576, 1500, 1500, 1500},
		{"pppoe-1492", 576, 1500, 1492, 1492},
		{"gre-1476", 576, 1500, 1476, 1476},
		{"wg-1420", 576, 1500, 1420, 1420},
		{"vpn-1383", 576, 1500, 1383, 1383},
		{"ipv6-1280", 1280, 1500, 1280, 1280},
		{"odd-1273", 576, 1500, 1273, 1273},
		{"floor-576", 576, 1500, 576, 576},
		{"blocked-all", 576, 1500, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, steps := MTUSearch(tc.min, tc.max, func(size int) MTUStep {
				return MTUStep{Passed: size <= tc.trueLimit}
			})
			if got != tc.want {
				t.Fatalf("MTUSearch(%d,%d,limit=%d) = %d, want %d (steps=%+v)", tc.min, tc.max, tc.trueLimit, got, tc.want, steps)
			}
			// Verify staircase phases are non-increasing in step size (20 -> 5 -> 1)
			prevStep := 20
			for _, st := range steps {
				if st.Step > prevStep {
					t.Fatalf("step size increased from %d to %d in %+v", prevStep, st.Step, steps)
				}
				prevStep = st.Step
			}
		})
	}
}

func TestAnalyzeNAT(t *testing.T) {
	hop := func(ttl int, ip string) Hop {
		return Hop{TTL: ttl, Responders: []Responder{{IP: ip}}}
	}

	t.Run("direct", func(t *testing.T) {
		r := AnalyzeNAT("81.90.20.19", "81.90.20.19", []Hop{hop(1, "81.90.20.1"), hop(2, "1.1.1.1")})
		if r.Detected || r.Layers != 0 || r.Type != "none" || r.CGNAT {
			t.Fatalf("want direct, got %+v", r)
		}
	})

	t.Run("single-nat", func(t *testing.T) {
		r := AnalyzeNAT("192.168.1.50", "94.29.26.245", []Hop{hop(1, "192.168.1.1"), hop(2, "81.90.20.1")})
		if !r.Detected || r.Layers != 1 || r.Type != "single" || r.CGNAT {
			t.Fatalf("want single NAT, got %+v", r)
		}
	})

	t.Run("double-nat-cgnat", func(t *testing.T) {
		r := AnalyzeNAT("192.168.1.50", "94.29.26.245", []Hop{hop(1, "192.168.1.1"), hop(2, "100.64.10.1"), hop(3, "81.90.20.1")})
		if !r.Detected || r.Layers != 2 || r.Type != "double" || !r.CGNAT {
			t.Fatalf("want double NAT + CGNAT, got %+v", r)
		}
	})

	t.Run("triple-nat", func(t *testing.T) {
		r := AnalyzeNAT("192.168.1.50", "94.29.26.245", []Hop{
			hop(1, "192.168.1.1"),
			hop(2, "10.20.0.1"),
			hop(3, "100.64.5.1"),
			hop(4, "81.90.20.1"),
		})
		if !r.Detected || r.Layers != 3 || r.Type != "triple" || !r.CGNAT {
			t.Fatalf("want triple NAT + CGNAT, got %+v", r)
		}
	})

	t.Run("carrier-private-after-public-ignored", func(t *testing.T) {
		r := AnalyzeNAT("192.168.1.50", "94.29.26.245", []Hop{
			hop(1, "192.168.1.1"),
			hop(2, "81.90.20.1"),
			hop(3, "10.0.0.1"), // carrier MPLS hop after public
			hop(4, "1.1.1.1"),
		})
		if r.Layers != 1 || r.Type != "single" {
			t.Fatalf("post-public private hop should not count as client NAT: %+v", r)
		}
	})
}
