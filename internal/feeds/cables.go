package feeds

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Cable is one submarine cable system (TeleGeography Submarine Cable Map).
type Cable struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Color    string         `json:"color,omitempty"`
	Length   string         `json:"length,omitempty"` // as published: "45,000 km"
	RFS      string         `json:"rfs,omitempty"`    // ready for service: "2024" / "2026 Q3"
	RFSYear  int            `json:"rfs_year,omitempty"`
	Planned  bool           `json:"planned,omitempty"`
	Owners   string         `json:"owners,omitempty"`
	URL      string         `json:"url,omitempty"`
	Landing  []string       `json:"landing,omitempty"` // landing point ids
	Geometry [][][2]float64 `json:"geometry"`          // MultiLineString, [lon,lat]
}

// LandingPoint is a cable landing station.
type LandingPoint struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Country string  `json:"country,omitempty"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

// CableDB is the combined cable map kept in the cache.
type CableDB struct {
	Updated time.Time      `json:"updated"`
	Source  string         `json:"source"`
	Cables  []Cable        `json:"cables"`
	Landing []LandingPoint `json:"landing"`

	lp map[string]*LandingPoint
}

// CableDetail is the per-cable document (api/v3/cable/<id>.json).
type CableDetail struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Length        string `json:"length"`
	Owners        string `json:"owners"`
	RFS           string `json:"rfs"`
	RFSYear       int    `json:"rfs_year"`
	IsPlanned     bool   `json:"is_planned"`
	URL           string `json:"url"`
	LandingPoints []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Country string `json:"country"`
	} `json:"landing_points"`
}

type geoFC struct {
	Type     string `json:"type"`
	Features []struct {
		Properties map[string]any  `json:"properties"`
		Geometry   json.RawMessage `json:"geometry"`
	} `json:"features"`
}

func round5(v float64) float64 { return math.Round(v*1e5) / 1e5 }

// ParseCableGeo parses cable-geo.json (FeatureCollection of MultiLineStrings,
// several features may share one cable id) into cables with geometry only.
func ParseCableGeo(b []byte) ([]Cable, error) {
	var fc geoFC
	if err := json.Unmarshal(b, &fc); err != nil {
		return nil, fmt.Errorf("cable-geo: %w", err)
	}
	byID := map[string]int{}
	var out []Cable
	for _, f := range fc.Features {
		id, _ := f.Properties["id"].(string)
		if id == "" {
			continue
		}
		var g struct {
			Type        string          `json:"type"`
			Coordinates json.RawMessage `json:"coordinates"`
		}
		if json.Unmarshal(f.Geometry, &g) != nil {
			continue
		}
		var lines [][][2]float64
		switch g.Type {
		case "MultiLineString":
			_ = json.Unmarshal(g.Coordinates, &lines)
		case "LineString":
			var l [][2]float64
			if json.Unmarshal(g.Coordinates, &l) == nil {
				lines = [][][2]float64{l}
			}
		}
		for i := range lines {
			for j := range lines[i] {
				lines[i][j] = [2]float64{round5(lines[i][j][0]), round5(lines[i][j][1])}
			}
		}
		i, ok := byID[id]
		if !ok {
			name, _ := f.Properties["name"].(string)
			color, _ := f.Properties["color"].(string)
			byID[id] = len(out)
			out = append(out, Cable{ID: id, Name: name, Color: color})
			i = len(out) - 1
		}
		out[i].Geometry = append(out[i].Geometry, lines...)
	}
	if len(out) == 0 {
		return nil, errors.New("cable-geo: no cables")
	}
	return out, nil
}

// ParseLandingGeo parses landing-point-geo.json. Names are "City, Country".
func ParseLandingGeo(b []byte) ([]LandingPoint, error) {
	var fc geoFC
	if err := json.Unmarshal(b, &fc); err != nil {
		return nil, fmt.Errorf("landing-point-geo: %w", err)
	}
	var out []LandingPoint
	for _, f := range fc.Features {
		id, _ := f.Properties["id"].(string)
		name, _ := f.Properties["name"].(string)
		var g struct {
			Type        string     `json:"type"`
			Coordinates [2]float64 `json:"coordinates"`
		}
		if id == "" || json.Unmarshal(f.Geometry, &g) != nil || g.Type != "Point" {
			continue
		}
		lp := LandingPoint{ID: id, Name: name, Lon: round5(g.Coordinates[0]), Lat: round5(g.Coordinates[1])}
		if i := strings.LastIndex(name, ", "); i >= 0 {
			lp.Country = name[i+2:]
		}
		out = append(out, lp)
	}
	if len(out) == 0 {
		return nil, errors.New("landing-point-geo: no points")
	}
	return out, nil
}

// Apply merges a per-cable detail document into c.
func (c *Cable) Apply(d *CableDetail) {
	if d == nil {
		return
	}
	if d.Name != "" {
		c.Name = d.Name
	}
	c.Length, c.Owners, c.RFS, c.RFSYear, c.Planned, c.URL = d.Length, d.Owners, d.RFS, d.RFSYear, d.IsPlanned, d.URL
	c.Landing = c.Landing[:0]
	for _, l := range d.LandingPoints {
		c.Landing = append(c.Landing, l.ID)
	}
}

func (db *CableDB) index() {
	if db.lp != nil {
		return
	}
	db.lp = make(map[string]*LandingPoint, len(db.Landing))
	for i := range db.Landing {
		db.lp[db.Landing[i].ID] = &db.Landing[i]
	}
}

// Point returns the landing point by id.
func (db *CableDB) Point(id string) *LandingPoint {
	db.index()
	return db.lp[id]
}

// LengthKm parses "45,000 km" → 45000 (0 when unknown).
func LengthKm(s string) float64 {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "km")
	s = strings.ReplaceAll(strings.TrimSpace(s), ",", "")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

// GeoJSON renders the cables as a FeatureCollection (properties for map popups).
func (db *CableDB) GeoJSON() map[string]any {
	db.index()
	feats := make([]any, 0, len(db.Cables))
	for _, c := range db.Cables {
		var st []string
		for _, id := range c.Landing {
			if p := db.lp[id]; p != nil {
				st = append(st, p.Name)
			}
		}
		feats = append(feats, map[string]any{"type": "Feature", "id": len(feats),
			"geometry": map[string]any{"type": "MultiLineString", "coordinates": c.Geometry},
			"properties": map[string]any{"id": c.ID, "name": c.Name, "color": c.Color, "length": c.Length, "rfs": c.RFS,
				"planned": c.Planned, "owners": c.Owners, "url": c.URL, "landing": strings.Join(c.Landing, ","),
				"stations": strings.Join(st, "; "), "n_stations": len(st)}})
	}
	return map[string]any{"type": "FeatureCollection", "features": feats}
}

// LandingGeoJSON renders the landing points (with the cables landing there).
func (db *CableDB) LandingGeoJSON() map[string]any {
	db.index()
	cab := map[string][]string{}
	for _, c := range db.Cables {
		for _, id := range c.Landing {
			cab[id] = append(cab[id], c.Name)
		}
	}
	feats := make([]any, 0, len(db.Landing))
	for _, p := range db.Landing {
		feats = append(feats, map[string]any{"type": "Feature",
			"geometry":   map[string]any{"type": "Point", "coordinates": []float64{p.Lon, p.Lat}},
			"properties": map[string]any{"id": p.ID, "name": p.Name, "cables": strings.Join(cab[p.ID], "; "), "n": len(cab[p.ID])}})
	}
	return map[string]any{"type": "FeatureCollection", "features": feats}
}

// ---------------- nearest-cable heuristic ----------------

// CableHint is a cable that could carry a long hop-to-hop segment.
type CableHint struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Length   string  `json:"length,omitempty"`
	RFS      string  `json:"rfs,omitempty"`
	FromName string  `json:"from"` // landing point near segment start
	ToName   string  `json:"to"`
	FromKm   float64 `json:"from_km"`
	ToKm     float64 `json:"to_km"`
}

// MinSuggestKm is the shortest segment worth a cable hint.
const MinSuggestKm = 1000

// HaversineKm is the great-circle distance.
func HaversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp, dl := (lat2-lat1)*math.Pi/180, (lon2-lon1)*math.Pi/180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return 2 * r * math.Asin(math.Min(1, math.Sqrt(a)))
}

// Suggest lists cables whose landing stations lie near both ends of a long
// segment a→b (lat/lon of the two hops). It is a heuristic: a cable that
// lands near both cities *could* carry the traffic, nothing proves it does.
// Planned cables (not yet in service) are skipped. n caps the result.
func (db *CableDB) Suggest(aLat, aLon, bLat, bLon float64, n int) []CableHint {
	if db == nil {
		return nil
	}
	seg := HaversineKm(aLat, aLon, bLat, bLon)
	if seg < MinSuggestKm {
		return nil
	}
	db.index()
	reach := math.Max(250, math.Min(900, 0.2*seg))
	type cand struct {
		h     CableHint
		score float64
	}
	var cs []cand
	for _, c := range db.Cables {
		if c.Planned || len(c.Landing) < 2 {
			continue
		}
		var pa, pb *LandingPoint
		da, db2 := math.Inf(1), math.Inf(1)
		for _, id := range c.Landing {
			p := db.lp[id]
			if p == nil {
				continue
			}
			if d := HaversineKm(aLat, aLon, p.Lat, p.Lon); d < da {
				da, pa = d, p
			}
			if d := HaversineKm(bLat, bLon, p.Lat, p.Lon); d < db2 {
				db2, pb = d, p
			}
		}
		if pa == nil || pb == nil || pa == pb || da > reach || db2 > reach {
			continue
		}
		// the cable must actually span the gap: its two stations far apart
		if HaversineKm(pa.Lat, pa.Lon, pb.Lat, pb.Lon) < 0.5*seg {
			continue
		}
		cs = append(cs, cand{CableHint{ID: c.ID, Name: c.Name, Length: c.Length, RFS: c.RFS, FromName: pa.Name, ToName: pb.Name,
			FromKm: math.Round(da), ToKm: math.Round(db2)}, da + db2})
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].score != cs[j].score {
			return cs[i].score < cs[j].score
		}
		return cs[i].h.Name < cs[j].h.Name
	})
	if n <= 0 {
		n = 3
	}
	var out []CableHint
	for i := 0; i < len(cs) && i < n; i++ {
		out = append(out, cs[i].h)
	}
	return out
}
