package backbone

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/PalMeany/traced-cli/internal/cache"
)

//go:embed data/backbones.json.gz
var builtinGz []byte

// Dataset is the built-in layer bundle.
type Dataset struct {
	Note   string               `json:"note,omitempty"`
	Layers []*FeatureCollection `json:"layers"`
}

var (
	builtinOnce sync.Once
	builtin     []*FeatureCollection
)

// DecodeDataset reads a gzipped (or plain) dataset.
func DecodeDataset(b []byte) (*Dataset, error) {
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		b, err = io.ReadAll(io.LimitReader(zr, 64<<20))
		if err != nil {
			return nil, err
		}
	}
	var d Dataset
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// EncodeDataset gzips a dataset.
func EncodeDataset(d *Dataset) ([]byte, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write(raw)
	zw.Close()
	return buf.Bytes(), nil
}

// Builtin returns the embedded layers (popular operators).
func Builtin() []*FeatureCollection {
	builtinOnce.Do(func() {
		d, err := DecodeDataset(builtinGz)
		if err != nil {
			return
		}
		for _, l := range d.Layers {
			if l.Meta != nil {
				l.Meta.Builtin = true
				for i := range l.Features {
					l.Features[i].Properties["builtin"] = true
				}
			}
		}
		builtin = d.Layers
	})
	return builtin
}

// Dir is where user layers live (~/.cache/traced/backbones).
func Dir() string { return filepath.Join(cache.Dir(), "backbones") }

func validSlug(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// Save stores a graph as a user layer and returns its path.
func Save(g *Graph) (string, error) {
	fc := g.GeoJSON()
	b, err := json.MarshalIndent(fc, "", " ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(Dir(), fc.Meta.Slug+".geojson")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}

// Remove deletes a user layer.
func Remove(slug string) error {
	slug = strings.TrimSuffix(slug, ".geojson")
	if !validSlug(slug) {
		return fmt.Errorf("invalid layer id %q", slug)
	}
	err := os.Remove(filepath.Join(Dir(), slug+".geojson"))
	if errors.Is(err, os.ErrNotExist) {
		for _, l := range Builtin() {
			if l.Meta.Slug == slug {
				return fmt.Errorf("%s is a built-in layer (it can be hidden on the map, not removed)", slug)
			}
		}
		return fmt.Errorf("no user layer %q (traced backbone list)", slug)
	}
	return err
}

// User reads the user layers (broken files are skipped).
func User() []*FeatureCollection {
	ents, _ := os.ReadDir(Dir())
	var out []*FeatureCollection
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".geojson") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(Dir(), e.Name()))
		if err != nil || len(b) > 64<<20 {
			continue
		}
		slug := strings.TrimSuffix(e.Name(), ".geojson")
		g, err := FromGeoJSON(b, "", 0)
		if err != nil {
			continue
		}
		fc := g.GeoJSON()
		fc.Meta.Slug = slug
		for i := range fc.Features {
			fc.Features[i].Properties["slug"] = slug
		}
		out = append(out, fc)
	}
	return out
}

// All is builtin + user layers (a user layer replaces a built-in one with
// the same id).
func All(withUser bool) []*FeatureCollection {
	var user []*FeatureCollection
	if withUser {
		user = User()
	}
	have := map[string]bool{}
	for _, l := range user {
		have[l.Meta.Slug] = true
	}
	out := append([]*FeatureCollection{}, user...)
	for _, l := range Builtin() {
		if !have[l.Meta.Slug] {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meta.Provider < out[j].Meta.Provider })
	return out
}

// Palette colours layers that carry no colour of their own.
var Palette = []string{"#ff6b6b", "#ffd166", "#06d6a0", "#4cc9f0", "#c77dff", "#f78c6b", "#90be6d", "#f15bb5", "#00bbf9", "#e9c46a", "#9b5de5", "#43aa8b"}

// Merge flattens layers into one FeatureCollection for the map; every link
// gets a "lid" (slug:index) and every feature a display colour.
func Merge(ls []*FeatureCollection) map[string]any {
	feats := []any{}
	var metas []Meta
	for i, l := range ls {
		col := Palette[i%len(Palette)]
		m := *l.Meta
		m.Color = col
		metas = append(metas, m)
		li := 0
		for _, f := range l.Features {
			p := map[string]any{}
			for k, v := range f.Properties {
				p[k] = v
			}
			p["color"] = col
			if f.Geometry.Type == "LineString" {
				p["lid"] = fmt.Sprintf("%s:%d", m.Slug, li)
				li++
			}
			feats = append(feats, map[string]any{"type": "Feature", "geometry": f.Geometry, "properties": p})
		}
	}
	return map[string]any{"type": "FeatureCollection", "features": feats, "layers": metas}
}

// ---------------- trace hints ----------------

// HopPoint is a located hop of a trace.
type HopPoint struct {
	TTL      int
	ASN      int
	Lat, Lon float64
	Located  bool
	Label    string
}

// Hint: the trace crosses an AS whose backbone is in the dataset.
type Hint struct {
	Slug     string    `json:"slug"`
	Provider string    `json:"provider"`
	ASN      int       `json:"asn"`
	TTLs     []int     `json:"ttls"`
	Links    []HintRef `json:"links,omitempty"` // backbone links joining consecutive hops of this AS
}

// HintRef names a matched link.
type HintRef struct {
	LID      string  `json:"lid"`
	From     string  `json:"from,omitempty"`
	To       string  `json:"to,omitempty"`
	FromTTL  int     `json:"from_ttl"`
	ToTTL    int     `json:"to_ttl"`
	Distance float64 `json:"km"` // how far the link ends are from the hops
}

// Hints matches the ASNs of the path against the layers' ASNs and, for
// consecutive located hops inside one AS, the backbone links (or chains of
// two links) whose end cities lie near both hops. Heuristic, like the cable
// hints: a matching link could carry the traffic.
func Hints(ls []*FeatureCollection, hops []HopPoint) []Hint {
	byASN := map[int][]*FeatureCollection{}
	for _, l := range ls {
		if l.Meta != nil && l.Meta.ASN > 0 {
			byASN[l.Meta.ASN] = append(byASN[l.Meta.ASN], l)
		}
	}
	var out []Hint
	seen := map[string]int{}
	for _, h := range hops {
		for _, l := range byASN[h.ASN] {
			i, ok := seen[l.Meta.Slug]
			if !ok {
				i = len(out)
				seen[l.Meta.Slug] = i
				out = append(out, Hint{Slug: l.Meta.Slug, Provider: l.Meta.Provider, ASN: h.ASN})
			}
			if n := len(out[i].TTLs); n == 0 || out[i].TTLs[n-1] != h.TTL {
				out[i].TTLs = append(out[i].TTLs, h.TTL)
			}
		}
	}
	for hi := range out {
		var l *FeatureCollection
		for _, c := range byASN[out[hi].ASN] {
			if c.Meta.Slug == out[hi].Slug {
				l = c
			}
		}
		type seg struct {
			lid      string
			from, to string
			a, b     [2]float64
		}
		var segs []seg
		li := 0
		for _, f := range l.Features {
			if f.Geometry.Type != "LineString" {
				continue
			}
			var c [][2]float64
			if json.Unmarshal(f.Geometry.Coordinates, &c) == nil && len(c) >= 2 {
				fr, _ := f.Properties["from"].(string)
				to, _ := f.Properties["to"].(string)
				segs = append(segs, seg{fmt.Sprintf("%s:%d", l.Meta.Slug, li), fr, to, c[0], c[len(c)-1]})
			}
			li++
		}
		var pts []HopPoint
		for _, h := range hops {
			if h.ASN == out[hi].ASN && h.Located {
				pts = append(pts, h)
			}
		}
		for i := 1; i < len(pts); i++ {
			a, b := pts[i-1], pts[i]
			km := haversine(a.Lat, a.Lon, b.Lat, b.Lon)
			if km < 80 {
				continue // same metro
			}
			reach := math.Max(60, math.Min(250, 0.25*km))
			best, bd := -1, math.Inf(1)
			for si, s := range segs {
				d1 := haversine(a.Lat, a.Lon, s.a[1], s.a[0]) + haversine(b.Lat, b.Lon, s.b[1], s.b[0])
				d2 := haversine(a.Lat, a.Lon, s.b[1], s.b[0]) + haversine(b.Lat, b.Lon, s.a[1], s.a[0])
				d := math.Min(d1, d2)
				if d < bd {
					bd, best = d, si
				}
			}
			if best >= 0 && bd <= 2*reach {
				s := segs[best]
				out[hi].Links = append(out[hi].Links, HintRef{LID: s.lid, From: s.from, To: s.to, FromTTL: a.TTL, ToTTL: b.TTL, Distance: math.Round(bd)})
			}
			if len(out[hi].Links) >= 12 {
				break
			}
		}
	}
	return out
}
