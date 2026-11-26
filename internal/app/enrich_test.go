package app

import (
	"testing"

	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/trace"
)

func hop(ttl int, lat, lon float64, city string) trace.Hop {
	return trace.Hop{TTL: ttl, Responders: []trace.Responder{{IP: "192.0.2.1", Geo: &geo.Info{City: city, Lat: lat, Lon: lon, Located: true}}}}
}

func TestCableHints(t *testing.T) {
	db := &feeds.CableDB{
		Landing: []feeds.LandingPoint{{ID: "dk", Name: "Blaabjerg, Denmark", Lat: 55.6, Lon: 8.1}, {ID: "nj", Name: "Wall Township, NJ", Lat: 40.15, Lon: -74.06}},
		Cables:  []feeds.Cable{{ID: "havfrue", Name: "Havfrue/AEC-2", Landing: []string{"dk", "nj"}}},
	}
	hops := []trace.Hop{hop(10, 59.33, 18.06, "Stockholm"), hop(11, 55.68, 12.57, "Copenhagen"), {TTL: 12}, hop(13, 40.71, -74.0, "New York")}
	h := CableHints(db, hops)
	if len(h) != 1 || h[0].FromTTL != 11 || h[0].ToTTL != 13 || h[0].Cables[0].ID != "havfrue" {
		t.Fatalf("%+v", h)
	}
	if CableHints(nil, hops) != nil {
		t.Fatal("nil db")
	}
}
