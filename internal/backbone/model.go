// Package backbone extracts terrestrial provider backbones (cities/PoPs and
// the links between them) from network map pictures — raster (PNG/JPEG/WebP)
// or SVG — and keeps them as GeoJSON layers for the web map and trace hints.
//
// Two engines produce the same graph: a vision LLM (OpenAI compatible or
// Gemini) that reads city names and links off the picture, and a local
// CV/vector engine (colour mask → Zhang-Suen skeleton → polyline graph →
// Douglas-Peucker → lon/lat through a geographic reference) that needs no key.
package backbone

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
)

// Node is a city / PoP of a backbone.
type Node struct {
	ID      string  `json:"id"`
	Name    string  `json:"name,omitempty"`
	Country string  `json:"country,omitempty"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Geo     string  `json:"geo,omitempty"` // how the position was found: builtin|peeringdb|nominatim|cache|image
}

// Link is a backbone segment between two nodes (or a free polyline traced
// off a picture when its ends are not named).
type Link struct {
	From   string       `json:"from,omitempty"` // node ids
	To     string       `json:"to,omitempty"`
	Label  string       `json:"label,omitempty"` // capacity / name as printed
	Coords [][2]float64 `json:"coords"`          // [lon,lat]
}

// Graph is one provider backbone.
type Graph struct {
	Provider string   `json:"provider"`
	ASN      int      `json:"asn,omitempty"`
	Source   string   `json:"source,omitempty"`    // file name or URL of the picture
	ParsedBy string   `json:"parsed_by,omitempty"` // engine: llm:<model>|cv|svg|import
	Color    string   `json:"color,omitempty"`
	Nodes    []Node   `json:"nodes"`
	Links    []Link   `json:"links"`
	Notes    []string `json:"notes,omitempty"`
}

// Slug is the file-safe id of a provider layer ("hurricane-electric-as6939").
func Slug(provider string, asn int) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(provider) {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "backbone"
	}
	if asn > 0 && !strings.Contains(s, fmt.Sprintf("as%d", asn)) {
		s += fmt.Sprintf("-as%d", asn)
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func (g *Graph) node(id string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

// Validate drops impossible coordinates and dangling links; it returns an
// error when nothing usable is left.
func (g *Graph) Validate() error {
	ok := func(lon, lat float64) bool {
		return !math.IsNaN(lon) && !math.IsNaN(lat) && lon >= -180 && lon <= 180 && lat >= -85.1 && lat <= 85.1
	}
	nodes := g.Nodes[:0]
	for _, n := range g.Nodes {
		if ok(n.Lon, n.Lat) && !(n.Lat == 0 && n.Lon == 0) {
			n.Lat, n.Lon = round5(n.Lat), round5(n.Lon)
			nodes = append(nodes, n)
		}
	}
	g.Nodes = nodes
	links := g.Links[:0]
	for _, l := range g.Links {
		if l.From != "" && g.node(l.From) == nil || l.To != "" && g.node(l.To) == nil {
			continue
		}
		good := len(l.Coords) >= 2
		for i, c := range l.Coords {
			if !ok(wrapLon(c[0]), c[1]) || math.Abs(c[0]) > 360 {
				good = false
				break
			}
			l.Coords[i] = [2]float64{round5(c[0]), round5(c[1])}
		}
		if good {
			links = append(links, l)
		}
	}
	g.Links = links
	if len(g.Links) == 0 && len(g.Nodes) == 0 {
		return errors.New("no valid nodes or links")
	}
	return nil
}

func round5(v float64) float64 { return math.Round(v*1e5) / 1e5 }

// LinkByNames connects two nodes with a straight (great-circle sampled for
// long hops) line.
func (g *Graph) LinkByNames(from, to, label string) bool {
	a, b := g.node(from), g.node(to)
	if a == nil || b == nil || a == b {
		return false
	}
	for _, l := range g.Links {
		if l.From == from && l.To == to || l.From == to && l.To == from {
			return false
		}
	}
	g.Links = append(g.Links, Link{From: from, To: to, Label: label, Coords: arc(a.Lon, a.Lat, b.Lon, b.Lat)})
	return true
}

// arc samples a great circle every ~400 km so long links bend like on the map.
func arc(lon1, lat1, lon2, lat2 float64) [][2]float64 {
	km := haversine(lat1, lon1, lat2, lon2)
	n := int(km / 400)
	if n < 1 || math.Abs(lon2-lon1) > 180 {
		return [][2]float64{{lon1, lat1}, {lon2, lat2}}
	}
	if n > 32 {
		n = 32
	}
	r := math.Pi / 180
	p1, l1, p2, l2 := lat1*r, lon1*r, lat2*r, lon2*r
	d := km / 6371
	out := make([][2]float64, 0, n+1)
	for i := 0; i <= n; i++ {
		f := float64(i) / float64(n)
		a := math.Sin((1-f)*d) / math.Sin(d)
		b := math.Sin(f*d) / math.Sin(d)
		x := a*math.Cos(p1)*math.Cos(l1) + b*math.Cos(p2)*math.Cos(l2)
		y := a*math.Cos(p1)*math.Sin(l1) + b*math.Cos(p2)*math.Sin(l2)
		z := a*math.Sin(p1) + b*math.Sin(p2)
		out = append(out, [2]float64{math.Atan2(y, x) / r, math.Atan2(z, math.Sqrt(x*x+y*y)) / r})
	}
	return out
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp, dl := (lat2-lat1)*math.Pi/180, (lon2-lon1)*math.Pi/180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return 2 * R * math.Asin(math.Min(1, math.Sqrt(a)))
}

// ---------------- GeoJSON ----------------

// FeatureCollection is the on-disk / API format of a layer.
type FeatureCollection struct {
	Type     string    `json:"type"`
	Name     string    `json:"name,omitempty"`
	Meta     *Meta     `json:"traced,omitempty"`
	Features []Feature `json:"features"`
}

// Meta is the layer header (non-standard member, ignored by GeoJSON tools).
type Meta struct {
	Slug     string   `json:"slug"`
	Provider string   `json:"provider"`
	ASN      int      `json:"asn,omitempty"`
	Source   string   `json:"source,omitempty"`
	ParsedBy string   `json:"parsed_by,omitempty"`
	Color    string   `json:"color,omitempty"`
	Nodes    int      `json:"nodes"`
	Links    int      `json:"links"`
	Builtin  bool     `json:"builtin,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// Feature is a GeoJSON feature with a LineString or Point geometry.
type Feature struct {
	Type       string         `json:"type"`
	Geometry   Geometry       `json:"geometry"`
	Properties map[string]any `json:"properties"`
}

// Geometry holds LineString / MultiLineString / Point coordinates.
type Geometry struct {
	Type        string          `json:"type"`
	Coordinates json.RawMessage `json:"coordinates"`
}

func rawCoords(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// GeoJSON renders the graph: LineString per link, Point per node.
func (g *Graph) GeoJSON() *FeatureCollection {
	slug := Slug(g.Provider, g.ASN)
	fc := &FeatureCollection{Type: "FeatureCollection", Name: g.Provider,
		Meta: &Meta{Slug: slug, Provider: g.Provider, ASN: g.ASN, Source: g.Source, ParsedBy: g.ParsedBy, Color: g.Color,
			Nodes: len(g.Nodes), Links: len(g.Links), Notes: g.Notes}}
	base := func(kind string) map[string]any {
		p := map[string]any{"kind": kind, "provider": g.Provider, "slug": slug, "source": g.Source, "parsed_by": g.ParsedBy}
		if g.ASN > 0 {
			p["asn"] = g.ASN
		}
		if g.Color != "" {
			p["color"] = g.Color
		}
		return p
	}
	for _, l := range g.Links {
		p := base("link")
		name := func(id string) string {
			if n := g.node(id); n != nil && n.Name != "" {
				return n.Name
			}
			return id
		}
		if l.From != "" {
			p["from"] = name(l.From)
		}
		if l.To != "" {
			p["to"] = name(l.To)
		}
		if l.Label != "" {
			p["label"] = l.Label
		}
		fc.Features = append(fc.Features, Feature{Type: "Feature", Geometry: Geometry{Type: "LineString", Coordinates: rawCoords(l.Coords)}, Properties: p})
	}
	for _, n := range g.Nodes {
		p := base("node")
		p["id"], p["name"] = n.ID, n.Name
		if n.Country != "" {
			p["country"] = n.Country
		}
		if n.Geo != "" {
			p["geo"] = n.Geo
		}
		fc.Features = append(fc.Features, Feature{Type: "Feature", Geometry: Geometry{Type: "Point", Coordinates: rawCoords([2]float64{n.Lon, n.Lat})}, Properties: p})
	}
	if fc.Features == nil {
		fc.Features = []Feature{}
	}
	return fc
}

// FromGeoJSON reads any FeatureCollection (ours or a foreign one with
// LineString / MultiLineString / Point features) into a graph. provider/asn
// override the values stored in the file when set.
func FromGeoJSON(b []byte, provider string, asn int) (*Graph, error) {
	var fc FeatureCollection
	if err := json.Unmarshal(b, &fc); err != nil {
		return nil, fmt.Errorf("geojson: %w", err)
	}
	if fc.Type != "FeatureCollection" {
		return nil, errors.New("geojson: FeatureCollection expected")
	}
	g := &Graph{Provider: provider, ASN: asn, ParsedBy: "import"}
	if m := fc.Meta; m != nil {
		if g.Provider == "" {
			g.Provider = m.Provider
		}
		if g.ASN == 0 {
			g.ASN = m.ASN
		}
		g.Source, g.Color, g.Notes = m.Source, m.Color, m.Notes
		if m.ParsedBy != "" {
			g.ParsedBy = m.ParsedBy
		}
	}
	str := func(p map[string]any, keys ...string) string {
		for _, k := range keys {
			if v, ok := p[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	byName := map[string]string{}
	for _, f := range fc.Features {
		p := f.Properties
		if p == nil {
			p = map[string]any{}
		}
		if g.Provider == "" {
			g.Provider = str(p, "provider", "operator")
		}
		if g.ASN == 0 {
			if v, ok := p["asn"].(float64); ok {
				g.ASN = int(v)
			}
		}
		if g.Source == "" {
			g.Source = str(p, "source")
		}
		switch f.Geometry.Type {
		case "Point":
			var c [2]float64
			if json.Unmarshal(f.Geometry.Coordinates, &c) != nil {
				continue
			}
			name := str(p, "name", "city", "title", "label")
			id := str(p, "id")
			if id == "" {
				id = nodeID(name)
			}
			if id == "" {
				id = fmt.Sprintf("n%d", len(g.Nodes)+1)
			}
			if g.node(id) != nil {
				continue
			}
			g.Nodes = append(g.Nodes, Node{ID: id, Name: name, Country: str(p, "country", "cc"), Lon: c[0], Lat: c[1], Geo: orStr(str(p, "geo"), "import")})
			if name != "" {
				byName[name] = id
			}
		case "LineString":
			var c [][2]float64
			if json.Unmarshal(f.Geometry.Coordinates, &c) == nil {
				g.Links = append(g.Links, Link{From: str(p, "from"), To: str(p, "to"), Label: str(p, "label", "name", "capacity"), Coords: c})
			}
		case "MultiLineString":
			var cs [][][2]float64
			if json.Unmarshal(f.Geometry.Coordinates, &cs) == nil {
				for _, c := range cs {
					g.Links = append(g.Links, Link{Label: str(p, "label", "name"), Coords: c})
				}
			}
		}
	}
	// link ends are stored as names in our files; map them back to ids
	for i := range g.Links {
		for _, e := range []*string{&g.Links[i].From, &g.Links[i].To} {
			if *e == "" || g.node(*e) != nil {
				continue
			}
			if id, ok := byName[*e]; ok {
				*e = id
			} else {
				*e = ""
			}
		}
	}
	if g.Provider == "" {
		return nil, errors.New("provider name required (--provider)")
	}
	return g, g.Validate()
}

func orStr(s, d string) string {
	if s != "" {
		return s
	}
	return d
}

func nodeID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Providers lists the distinct providers of a set of layers.
func Providers(ls []*FeatureCollection) []Meta {
	var out []Meta
	for _, l := range ls {
		if l.Meta != nil {
			out = append(out, *l.Meta)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// Distance is the great-circle distance in km.
func Distance(lat1, lon1, lat2, lon2 float64) float64 { return haversine(lat1, lon1, lat2, lon2) }
