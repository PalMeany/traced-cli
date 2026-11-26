package backbone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PalMeany/traced-cli/internal/feeds"
)

var cities = map[string][2]float64{ // lon, lat
	"London": {-0.1276, 51.5072}, "Amsterdam": {4.9041, 52.3676}, "Frankfurt": {8.6821, 50.1109},
	"Paris": {2.3522, 48.8566}, "Moscow": {37.6173, 55.7558}, "Stockholm": {18.0686, 59.3293}, "Madrid": {-3.7038, 40.4168},
}

func drawLine(img *image.RGBA, x0, y0, x1, y1, w float64, c color.Color) {
	n := int(math.Hypot(x1-x0, y1-y0)*2) + 1
	for i := 0; i <= n; i++ {
		t := float64(i) / float64(n)
		cx, cy := x0+(x1-x0)*t, y0+(y1-y0)*t
		for dy := -w; dy <= w; dy++ {
			for dx := -w; dx <= w; dx++ {
				if dx*dx+dy*dy <= w*w {
					img.Set(int(math.Round(cx+dx)), int(math.Round(cy+dy)), c)
				}
			}
		}
	}
}

// synthetic map: equirect 10 px/deg over -20..60 lon, 30..70 lat
func syntheticPNG(t *testing.T) ([]byte, *GeoRef) {
	img := image.NewRGBA(image.Rect(0, 0, 800, 400))
	for i := range img.Pix {
		img.Pix[i] = 0xf4
	}
	ref := FromBBox([4]float64{-20, 30, 60, 70}, 800, 400, Equirect)
	land := color.RGBA{0xd9, 0xd4, 0xc8, 255}
	for y := 120; y < 330; y++ { // a land blob (fill, must be ignored)
		for x := 150; x < 600; x++ {
			img.Set(x, y, land)
		}
	}
	red := color.RGBA{0xe0, 0x1b, 0x24, 255}
	px := func(n string) (float64, float64) { c := cities[n]; return ref.Pixel(c[0], c[1]) }
	for _, e := range [][2]string{{"London", "Amsterdam"}, {"Amsterdam", "Frankfurt"}, {"Frankfurt", "Paris"}, {"Frankfurt", "Moscow"}, {"Paris", "Madrid"}} {
		x0, y0 := px(e[0])
		x1, y1 := px(e[1])
		drawLine(img, x0, y0, x1, y1, 1.6, red)
	}
	// legend speck of the same colour and blue text-like noise
	drawLine(img, 700, 380, 703, 380, 1, red)
	blue := color.RGBA{0x10, 0x40, 0xd0, 255}
	for i := 0; i < 5; i++ {
		drawLine(img, 20+float64(i*6), 20, 22+float64(i*6), 26, 0.6, blue)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), ref
}

func nearNode(g *Graph, name string, km float64) *Node {
	c := cities[name]
	for i := range g.Nodes {
		if haversine(g.Nodes[i].Lat, g.Nodes[i].Lon, c[1], c[0]) <= km {
			return &g.Nodes[i]
		}
	}
	return nil
}

func TestThinBar(t *testing.T) {
	w, h := 40, 20
	m := make([]bool, w*h)
	for y := 6; y < 13; y++ {
		for x := 3; x < 37; x++ {
			m[y*w+x] = true
		}
	}
	Thin(m, w, h)
	for x := 8; x < 32; x++ {
		n := 0
		for y := 0; y < h; y++ {
			if m[y*w+x] {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("column %d has %d skeleton pixels", x, n)
		}
	}
}

func TestSimplify(t *testing.T) {
	var pts [][2]float64
	for i := 0; i <= 100; i++ {
		pts = append(pts, [2]float64{float64(i), 0.2 * math.Sin(float64(i))})
	}
	pts = append(pts, [2]float64{100, 50})
	s := Simplify(pts, 1)
	if len(s) != 3 || s[1] != [2]float64{100, pts[100][1]} {
		t.Fatalf("%v", s)
	}
}

func TestRasterEngine(t *testing.T) {
	b, _ := syntheticPNG(t)
	img, _, _ := DecodeImage(b)
	cands := DetectLineColors(img, 1200)
	if len(cands) == 0 || colorDist(hexRGBA(cands[0].Color), color.RGBA{0xe0, 0x1b, 0x24, 255}) > 40 {
		t.Fatalf("auto colour: %+v", cands)
	}
	g, err := ParseRaster(b, RefOptions{BBox: "-20,30,60,70", Proj: "equirect"}, CVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Links) < 5 || len(g.Links) > 7 {
		t.Fatalf("links: %d %+v", len(g.Links), g.Links)
	}
	for _, c := range []string{"London", "Frankfurt", "Moscow", "Madrid", "Amsterdam", "Paris"} {
		n := nearNode(g, c, 25)
		if n == nil {
			t.Fatalf("no node near %s: %+v", c, g.Nodes)
		}
		if n.Name != c {
			t.Errorf("node near %s named %q", c, n.Name)
		}
	}
	// a link Frankfurt—Moscow traced as one polyline
	found := false
	for _, l := range g.Links {
		if l.From == "frankfurt" && l.To == "moscow" || l.From == "moscow" && l.To == "frankfurt" {
			found = true
			if len(l.Coords) > 6 {
				t.Errorf("straight link not simplified: %d points", len(l.Coords))
			}
		}
	}
	if !found {
		t.Fatalf("frankfurt-moscow missing: %+v", g.Links)
	}
	// explicit colour and mercator region preset still parse
	if _, err := ParseRaster(b, RefOptions{Region: "europe"}, CVOptions{Color: "#e01b24"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRaster(b, RefOptions{}, CVOptions{}); err == nil || !strings.Contains(err.Error(), "reference") {
		t.Fatalf("missing ref: %v", err)
	}
}

func TestGeoRef(t *testing.T) {
	r := FromBBox(Regions["europe"], 1000, 800, Mercator)
	x, y := r.Pixel(8.68, 50.11)
	lon, lat := r.LonLat(x, y)
	if math.Abs(lon-8.68) > 1e-6 || math.Abs(lat-50.11) > 1e-6 {
		t.Fatal(lon, lat)
	}
	g, err := FromGCPs([]GCP{{X: 100, Y: 100, Lon: -10, Lat: 60}, {X: 900, Y: 700, Lon: 40, Lat: 35}}, Mercator)
	if err != nil {
		t.Fatal(err)
	}
	lon, lat = g.LonLat(100, 100)
	if math.Abs(lon+10) > 1e-6 || math.Abs(lat-60) > 1e-6 {
		t.Fatal(lon, lat)
	}
	var gs []GCP
	for _, c := range cities {
		x, y := r.Pixel(c[0], c[1])
		gs = append(gs, GCP{X: x, Y: y, Lon: c[0], Lat: c[1]})
	}
	a, err := FromGCPs(gs, Mercator)
	if err != nil {
		t.Fatal(err)
	}
	lon, lat = a.LonLat(r.Pixel(30, 60))
	if math.Abs(lon-30) > 1e-6 || math.Abs(lat-60) > 1e-6 {
		t.Fatal(lon, lat)
	}
	if _, err := ParseGCP("10,20=30"); err == nil {
		t.Fatal("bad gcp accepted")
	}
	if _, err := ParseBBox("10,20,5,30"); err == nil {
		t.Fatal("bad bbox accepted")
	}
}

func TestPathPolylines(t *testing.T) {
	ls := PathPolylines("M10,10 L20,10 l0,10 h-10 z M50 50 C60 50 70 60 70 70 m5-5 5 5")
	if len(ls) != 3 {
		t.Fatalf("%d %v", len(ls), ls)
	}
	if ls[0][len(ls[0])-1] != [2]float64{10, 10} || ls[0][2] != [2]float64{20, 20} {
		t.Fatalf("%v", ls[0])
	}
	if ls[1][len(ls[1])-1] != [2]float64{70, 70} || len(ls[1]) != 9 {
		t.Fatalf("%v", ls[1])
	}
	if ls[2][0] != [2]float64{75, 65} || ls[2][1] != [2]float64{80, 70} {
		t.Fatalf("%v", ls[2])
	}
}

func syntheticSVG(withLabels bool) string {
	ref := FromBBox([4]float64{-20, 30, 60, 70}, 800, 400, Mercator)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 400" width="800" height="400">
<style>.bb{stroke:#0077cc;stroke-width:2;fill:none}</style>
<path d="M100 100 L700 100 L700 300 Z" stroke="#999999" fill="#eeeeee"/>
<g transform="translate(5,-3)">`)
	px := func(n string) (float64, float64) {
		c := cities[n]
		x, y := ref.Pixel(c[0], c[1])
		return x - 5, y + 3
	}
	for _, e := range [][2]string{{"London", "Amsterdam"}, {"Amsterdam", "Frankfurt"}, {"Frankfurt", "Moscow"}, {"Paris", "Frankfurt"}} {
		x0, y0 := px(e[0])
		x1, y1 := px(e[1])
		mx, my := (x0+x1)/2, (y0+y1)/2-4
		fmt.Fprintf(&b, `<path class="bb" d="M%.2f,%.2f Q%.2f,%.2f %.2f,%.2f"/>`+"\n", x0, y0, mx, my, x1, y1)
	}
	fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" style="stroke: rgb(0,119,204)"/>`, func() float64 { x, _ := px("Stockholm"); return x }(),
		func() float64 { _, y := px("Stockholm"); return y }(), func() float64 { x, _ := px("Amsterdam"); return x }(), func() float64 { _, y := px("Amsterdam"); return y }())
	for _, n := range []string{"London", "Amsterdam", "Frankfurt", "Moscow", "Paris", "Stockholm"} {
		x, y := px(n)
		fmt.Fprintf(&b, `<circle cx="%.2f" cy="%.2f" r="3" fill="#0077cc"/>`, x, y)
		if withLabels {
			fmt.Fprintf(&b, `<text x="%.2f" y="%.2f" font-size="9">%s</text>`, x, y, n)
		}
	}
	b.WriteString(`</g><text x="20" y="390">Legend</text></svg>`)
	return b.String()
}

func TestSVGEngine(t *testing.T) {
	ctx := context.Background()
	gc := &Geocoder{Offline: true, PDB: &feeds.PeeringDB{}, CachePath: filepath.Join(t.TempDir(), "g.json")}
	for _, tc := range []struct {
		name string
		ro   RefOptions
	}{{"bbox", RefOptions{BBox: "-20,30,60,70"}}, {"labels", RefOptions{}}} {
		g, err := ParseSVG(ctx, []byte(syntheticSVG(true)), tc.ro, SVGOptions{}, gc)
		if err != nil {
			t.Fatal(tc.name, err)
		}
		if g.Color != "#0077cc" {
			t.Errorf("%s colour %s", tc.name, g.Color)
		}
		if len(g.Links) != 5 || len(g.Nodes) != 6 {
			t.Fatalf("%s: %d links %d nodes %+v", tc.name, len(g.Links), len(g.Nodes), g.Nodes)
		}
		for n := range cities {
			if n == "Madrid" {
				continue
			}
			nd := nearNode(g, n, 30)
			if nd == nil || nd.Name != n {
				t.Fatalf("%s: %s → %+v", tc.name, n, nd)
			}
		}
		ok := false
		for _, l := range g.Links {
			ok = ok || l.From == "frankfurt" && l.To == "moscow"
		}
		if !ok {
			t.Fatalf("%s: links %+v", tc.name, g.Links)
		}
	}
	if _, err := ParseSVG(ctx, []byte(syntheticSVG(false)), RefOptions{}, SVGOptions{}, gc); err == nil {
		t.Fatal("no labels and no bbox must fail")
	}
}

func TestLLMEngine(t *testing.T) {
	answer := `{"provider":"Example","nodes":[{"name":"Frankfurt","country":"DE"},{"name":"Amsterdam","country":"NL"},{"name":"Atlantis","country":""},{"name":"London (LON)","country":"GB"}],
"links":[{"from":"Frankfurt","to":"Amsterdam","label":"400G"},{"from":"Amsterdam","to":"London (LON)"},{"from":"London (LON)","to":"Atlantis"}]}`
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = nil
		json.Unmarshal(b, &got)
		switch {
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			if r.Header.Get("Authorization") != "Bearer k1" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "```json\n" + answer + "\n```"}}}})
		case strings.HasSuffix(r.URL.Path, "/models/gem:generateContent"):
			if r.Header.Get("x-goog-api-key") != "k2" {
				w.WriteHeader(403)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{
				map[string]any{"text": "thinking", "thought": true}, map[string]any{"text": answer}}}}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	pngb, _ := syntheticPNG(t)
	gc := &Geocoder{Offline: true, PDB: &feeds.PeeringDB{}, CachePath: filepath.Join(t.TempDir(), "g.json")}
	for _, v := range []*VisionConfig{{Kind: "openai", APIKey: "k1", BaseURL: srv.URL + "/v1", Model: "m"}, {Kind: "gemini", APIKey: "k2", BaseURL: srv.URL, Model: "gem"}} {
		g, err := Parse(context.Background(), pngb, Options{Provider: "Example", ASN: 64500, Engine: "auto", Vision: v, Geocoder: gc, Source: "x.png"})
		if err != nil {
			t.Fatal(v.Kind, err)
		}
		if len(g.Nodes) != 3 || len(g.Links) != 2 || g.Links[0].Label != "400G" || g.ParsedBy != "llm:"+v.Model {
			t.Fatalf("%s: %+v", v.Kind, g)
		}
		if len(g.Notes) == 0 || !strings.Contains(g.Notes[0], "Atlantis") {
			t.Fatalf("%s notes %v", v.Kind, g.Notes)
		}
		if nearNode(g, "London", 20) == nil {
			t.Fatal("london not geocoded")
		}
		js, _ := json.Marshal(got)
		if !strings.Contains(string(js), "image/png") {
			t.Fatalf("%s: picture not sent: %.200s", v.Kind, js)
		}
	}
	bad := &VisionConfig{Kind: "openai", APIKey: "wrong", BaseURL: srv.URL + "/v1", Model: "m"}
	if _, err := Parse(context.Background(), pngb, Options{Provider: "X", Engine: "llm", Vision: bad, Geocoder: gc}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("auth error: %v", err)
	}
	if _, err := Parse(context.Background(), pngb, Options{Provider: "X", Engine: "llm"}); err == nil {
		t.Fatal("llm without key must fail")
	}
	if _, err := ParseVisionJSON("sorry, no"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestGeocoder(t *testing.T) {
	ctx := context.Background()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("User-Agent") == "" || r.URL.Path != "/search" {
			w.WriteHeader(400)
			return
		}
		if strings.Contains(r.URL.RawQuery, "Smallville") {
			io.WriteString(w, `[{"lat":"38.1","lon":"-97.2","name":"Smallville","address":{"country_code":"us"}}]`)
			return
		}
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	cp := filepath.Join(t.TempDir(), "geocache.json")
	pdb := &feeds.PeeringDB{Fac: map[int]*feeds.Place{1: {ID: 1, Name: "DC1", City: "Tinytown", Country: "NL", Lat: 52, Lon: 5}, 2: {ID: 2, Name: "DC2", City: "Tinytown", Country: "NL", Lat: 52.2, Lon: 5.2}}}
	g := &Geocoder{NominatimURL: srv.URL, CachePath: cp, PDB: pdb}
	if p := g.Lookup(ctx, "Frankfurt", "DE"); p == nil || p.Source != "builtin" || math.Abs(p.Lat-50.11) > 0.1 {
		t.Fatalf("builtin: %+v", p)
	}
	if p := g.Lookup(ctx, "Tinytown", "Netherlands"); p == nil || p.Source != "peeringdb" || math.Abs(p.Lat-52.1) > 1e-9 {
		t.Fatalf("pdb: %+v", p)
	}
	if p := g.Lookup(ctx, "Smallville", "US"); p == nil || p.Source != "nominatim" || p.Country != "US" {
		t.Fatalf("nominatim: %+v", p)
	}
	if p := g.Lookup(ctx, "Nowhere", ""); p != nil {
		t.Fatalf("miss: %+v", p)
	}
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	n := calls
	g2 := &Geocoder{NominatimURL: srv.URL, CachePath: cp, PDB: pdb}
	if p := g2.Lookup(ctx, "Smallville", "US"); p == nil || p.Source != "cache" {
		t.Fatalf("cache: %+v", p)
	}
	if g2.Lookup(ctx, "Nowhere", "") != nil || calls != n {
		t.Fatalf("negative cache not used (%d calls)", calls-n)
	}
}

func TestGeoJSONRoundTripAndHints(t *testing.T) {
	g := &Graph{Provider: "Example Net", ASN: 64500, Source: "x.png", ParsedBy: "cv"}
	for _, n := range []string{"Frankfurt", "Amsterdam", "Moscow"} {
		c := cities[n]
		g.Nodes = append(g.Nodes, Node{ID: nodeID(n), Name: n, Lon: c[0], Lat: c[1]})
	}
	g.LinkByNames("frankfurt", "amsterdam", "100G")
	g.LinkByNames("frankfurt", "moscow", "")
	if g.LinkByNames("moscow", "frankfurt", "") {
		t.Fatal("duplicate link")
	}
	if len(g.Links[1].Coords) < 3 {
		t.Fatal("long link not sampled along the great circle")
	}
	g.Nodes = append(g.Nodes, Node{ID: "bad", Lat: 95, Lon: 10})
	if err := g.Validate(); err != nil || len(g.Nodes) != 3 {
		t.Fatal(err, g.Nodes)
	}
	b, _ := json.Marshal(g.GeoJSON())
	g2, err := FromGeoJSON(b, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if g2.Provider != "Example Net" || g2.ASN != 64500 || len(g2.Links) != 2 || g2.Links[0].From != "frankfurt" || g2.Links[0].Label != "100G" {
		t.Fatalf("%+v", g2)
	}
	if Slug("Example Net", 64500) != "example-net-as64500" || Slug("RETN AS9002", 9002) != "retn-as9002" {
		t.Fatal(Slug("Example Net", 64500), Slug("RETN AS9002", 9002))
	}
	hops := []HopPoint{{TTL: 3, ASN: 1}, {TTL: 5, ASN: 64500, Lat: 50.1, Lon: 8.7, Located: true}, {TTL: 6, ASN: 64500, Lat: 55.7, Lon: 37.6, Located: true}}
	hs := Hints([]*FeatureCollection{g.GeoJSON()}, hops)
	if len(hs) != 1 || hs[0].Slug != "example-net-as64500" || len(hs[0].TTLs) != 2 || len(hs[0].Links) != 1 || hs[0].Links[0].LID != "example-net-as64500:1" {
		t.Fatalf("%+v", hs)
	}
	m := Merge([]*FeatureCollection{g.GeoJSON()})
	if len(m["features"].([]any)) != 5 {
		t.Fatal("merge")
	}
}

func TestStore(t *testing.T) {
	t.Setenv("TRACED_CACHE_DIR", t.TempDir())
	g := &Graph{Provider: "Test Net", ASN: 64501, Nodes: []Node{{ID: "a", Name: "A", Lat: 50, Lon: 8}, {ID: "b", Name: "B", Lat: 52, Lon: 5}}}
	g.LinkByNames("a", "b", "")
	if _, err := Save(g); err != nil {
		t.Fatal(err)
	}
	us := User()
	if len(us) != 1 || us[0].Meta.Slug != "test-net-as64501" || us[0].Meta.Links != 1 {
		t.Fatalf("%+v", us)
	}
	if err := Remove("test-net-as64501"); err != nil {
		t.Fatal(err)
	}
	if err := Remove("../etc"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if len(Builtin()) < 10 {
		t.Fatalf("built-in dataset has %d layers", len(Builtin()))
	}
	for _, l := range Builtin() {
		if l.Meta == nil || l.Meta.Provider == "" || len(l.Features) == 0 {
			t.Fatalf("broken builtin layer %+v", l.Meta)
		}
		for _, f := range l.Features {
			if f.Geometry.Type == "Point" {
				var c [2]float64
				json.Unmarshal(f.Geometry.Coordinates, &c)
				if c[0] < -180 || c[0] > 180 || c[1] < -85 || c[1] > 85 || c == [2]float64{} {
					t.Fatalf("%s: bad point %v", l.Meta.Slug, c)
				}
			}
		}
	}
}

func TestGML(t *testing.T) {
	src := `graph [
  DateObtained "3/02/11"
  Network "Example"
  node [ id 0 label "Frankfurt" Country "Germany" Longitude 8.68 Latitude 50.11 Internal 1 ]
  node [ id 1 label "Amsterdam" Country "Netherlands" Longitude 4.9 Latitude 52.37 Internal 1 ]
  node [ id 2 label "Nowhere" Internal 1 ]
  edge [ source 0 target 1 LinkLabel "10G" ]
  edge [ source 1 target 2 ]
]`
	if !IsGML([]byte(src)) {
		t.Fatal("sniff")
	}
	g, err := FromGML([]byte(src), "", 3257, 0)
	if err != nil {
		t.Fatal(err)
	}
	if g.Provider != "Example" || len(g.Nodes) != 2 || len(g.Links) != 1 || g.Links[0].Label != "10G" || g.Nodes[0].Country != "DE" || len(g.Notes) != 3 {
		t.Fatalf("%+v", g)
	}
}

func TestLLMNamesakeDropped(t *testing.T) {
	// equirect picture of Europe; anchors are built-in hubs, "Tinytown" comes
	// from PeeringDB on the wrong continent while the picture puts it near Paris
	ref := FromBBox([4]float64{-20, 30, 60, 70}, 1000, 500, Equirect)
	pos := func(lon, lat float64) (float64, float64) { x, y := ref.Pixel(lon, lat); return x / 1000, y / 500 }
	var a VisionAnswer
	for n, c := range cities {
		x, y := pos(c[0], c[1])
		a.Nodes = append(a.Nodes, VisionNode{Name: n, X: x, Y: y})
	}
	x, y := pos(3.0, 49.5)
	a.Nodes = append(a.Nodes, VisionNode{Name: "Tinytown", X: x, Y: y})
	pdb := &feeds.PeeringDB{Fac: map[int]*feeds.Place{1: {ID: 1, City: "Tinytown", Country: "US", Lat: 38, Lon: -100}}}
	gc := &Geocoder{Offline: true, PDB: pdb, CachePath: filepath.Join(t.TempDir(), "g.json")}
	g := GraphFromAnswer(context.Background(), &a, gc)
	if g.node("tinytown") != nil || len(g.Nodes) != len(cities) || len(g.Notes) == 0 {
		t.Fatalf("%+v %v", g.Nodes, g.Notes)
	}
}

func TestLinkList(t *testing.T) {
	a, ok := LinkList([]byte(`{"links":[{"from":"Frankfurt","to":"Amsterdam","label":"400G"}]}`))
	if !ok || len(a.Nodes) != 2 {
		t.Fatalf("%+v", a)
	}
	if _, ok := LinkList([]byte(`{"type":"FeatureCollection","features":[]}`)); ok {
		t.Fatal("geojson taken for a link list")
	}
	gc := &Geocoder{Offline: true, PDB: &feeds.PeeringDB{}, CachePath: filepath.Join(t.TempDir(), "g.json")}
	g := GraphFromAnswer(context.Background(), a, gc)
	if len(g.Links) != 1 || g.Links[0].Label != "400G" {
		t.Fatalf("%+v", g)
	}
}
