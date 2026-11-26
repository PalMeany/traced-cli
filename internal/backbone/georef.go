package backbone

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Projection of the source picture.
type Projection string

const (
	Mercator Projection = "mercator" // web maps, most operator maps
	Equirect Projection = "equirect" // plate carrée
)

// Regions are bounding boxes (minLon,minLat,maxLon,maxLat) of typical map
// extents. They are a starting point: an exact --bbox or ground control
// points give much better positions.
var Regions = map[string][4]float64{
	"world":  {-180, -58, 180, 78},
	"europe": {-12, 34, 45, 71},
	"russia": {19, 40, 180, 78},
	"us":     {-125, 24, -66, 50},
	"na":     {-170, 10, -50, 75},
	"asia":   {60, -12, 150, 55},
	"latam":  {-120, -56, -30, 33},
}

// GCP is a ground control point: picture pixel → lon/lat.
type GCP struct {
	X, Y     float64
	Lon, Lat float64
}

// ParseGCP reads "px,py=lon,lat".
func ParseGCP(s string) (GCP, error) {
	l, r, ok := strings.Cut(s, "=")
	if !ok {
		return GCP{}, fmt.Errorf("gcp %q: want px,py=lon,lat", s)
	}
	a, err1 := floats(l, 2)
	b, err2 := floats(r, 2)
	if err1 != nil || err2 != nil {
		return GCP{}, fmt.Errorf("gcp %q: want px,py=lon,lat", s)
	}
	return GCP{X: a[0], Y: a[1], Lon: b[0], Lat: b[1]}, nil
}

// ParseBBox reads "minLon,minLat,maxLon,maxLat".
func ParseBBox(s string) ([4]float64, error) {
	v, err := floats(s, 4)
	if err != nil {
		return [4]float64{}, fmt.Errorf("bbox %q: want minLon,minLat,maxLon,maxLat", s)
	}
	b := [4]float64{v[0], v[1], v[2], v[3]}
	if b[0] >= b[2] || b[1] >= b[3] || b[0] < -180 || b[2] > 180 || b[1] < -85.1 || b[3] > 85.1 {
		return b, fmt.Errorf("bbox %q: out of range or empty", s)
	}
	return b, nil
}

func floats(s string, n int) ([]float64, error) {
	p := strings.Split(s, ",")
	if len(p) != n {
		return nil, errors.New("count")
	}
	out := make([]float64, n)
	for i := range p {
		v, err := strconv.ParseFloat(strings.TrimSpace(p[i]), 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, errors.New("number")
		}
		out[i] = v
	}
	return out, nil
}

func projY(p Projection, lat float64) float64 {
	if p == Equirect {
		return lat
	}
	lat = math.Max(-85.05, math.Min(85.05, lat))
	return math.Log(math.Tan(math.Pi/4+lat*math.Pi/360)) * 180 / math.Pi
}

func unprojY(p Projection, y float64) float64 {
	if p == Equirect {
		return y
	}
	return (2*math.Atan(math.Exp(y*math.Pi/180)) - math.Pi/2) * 180 / math.Pi
}

// GeoRef maps picture pixels to lon/lat: lon = a*x+b*y+c, Y = d*x+e*y+f in
// projected space (an affine transform; axis-aligned for a plain bbox).
type GeoRef struct {
	Proj Projection
	m    [6]float64
}

// FromBBox references a W×H picture whose edges are the bbox.
func FromBBox(bb [4]float64, w, h int, p Projection) *GeoRef {
	y0, y1 := projY(p, bb[3]), projY(p, bb[1]) // top, bottom
	return &GeoRef{Proj: p, m: [6]float64{(bb[2] - bb[0]) / float64(w), 0, bb[0], 0, (y1 - y0) / float64(h), y0}}
}

// FromGCPs fits the transform to control points: 2 points give an
// axis-aligned scale+offset, 3 or more a least-squares affine transform.
func FromGCPs(g []GCP, p Projection) (*GeoRef, error) {
	if len(g) < 2 {
		return nil, errors.New("at least 2 ground control points needed")
	}
	r := &GeoRef{Proj: p}
	if len(g) == 2 {
		a, b := g[0], g[1]
		if a.X == b.X || a.Y == b.Y {
			return nil, errors.New("control points must differ in both x and y")
		}
		ya, yb := projY(p, a.Lat), projY(p, b.Lat)
		sx := (b.Lon - a.Lon) / (b.X - a.X)
		sy := (yb - ya) / (b.Y - a.Y)
		r.m = [6]float64{sx, 0, a.Lon - sx*a.X, 0, sy, ya - sy*a.Y}
		return r, nil
	}
	// normal equations for [x y 1]·[a b c]ᵀ = lon and = Y
	var ata [3][3]float64
	var atl, aty [3]float64
	for _, c := range g {
		row := [3]float64{c.X, c.Y, 1}
		Y := projY(p, c.Lat)
		for i := 0; i < 3; i++ {
			for j := 0; j < 3; j++ {
				ata[i][j] += row[i] * row[j]
			}
			atl[i] += row[i] * c.Lon
			aty[i] += row[i] * Y
		}
	}
	s1, ok1 := solve3(ata, atl)
	s2, ok2 := solve3(ata, aty)
	if !ok1 || !ok2 {
		return nil, errors.New("control points are collinear")
	}
	r.m = [6]float64{s1[0], s1[1], s1[2], s2[0], s2[1], s2[2]}
	return r, nil
}

func solve3(a [3][3]float64, b [3]float64) ([3]float64, bool) {
	det := func(m [3][3]float64) float64 {
		return m[0][0]*(m[1][1]*m[2][2]-m[1][2]*m[2][1]) - m[0][1]*(m[1][0]*m[2][2]-m[1][2]*m[2][0]) + m[0][2]*(m[1][0]*m[2][1]-m[1][1]*m[2][0])
	}
	d := det(a)
	if math.Abs(d) < 1e-12 {
		return [3]float64{}, false
	}
	var x [3]float64
	for k := 0; k < 3; k++ {
		m := a
		for i := 0; i < 3; i++ {
			m[i][k] = b[i]
		}
		x[k] = det(m) / d
	}
	return x, true
}

// LonLat converts a pixel to lon/lat.
func (r *GeoRef) LonLat(x, y float64) (float64, float64) {
	lon := r.m[0]*x + r.m[1]*y + r.m[2]
	Y := r.m[3]*x + r.m[4]*y + r.m[5]
	return lon, unprojY(r.Proj, Y)
}

// Pixel is the inverse of LonLat (used by tests and label matching).
func (r *GeoRef) Pixel(lon, lat float64) (float64, float64) {
	Y := projY(r.Proj, lat)
	a, b, c, d, e, f := r.m[0], r.m[1], r.m[2], r.m[3], r.m[4], r.m[5]
	det := a*e - b*d
	if det == 0 {
		return math.NaN(), math.NaN()
	}
	u, v := lon-c, Y-f
	return (e*u - b*v) / det, (-d*u + a*v) / det
}

// RefOptions select the geographic reference of a picture.
type RefOptions struct {
	Region string
	BBox   string
	GCPs   []string
	Proj   string
}

// Build makes the reference for a w×h picture; nil without any option.
func (o RefOptions) Build(w, h int) (*GeoRef, error) {
	p := Mercator
	switch strings.ToLower(o.Proj) {
	case "", "mercator", "merc", "webmercator":
	case "equirect", "equirectangular", "platecarree", "latlon":
		p = Equirect
	default:
		return nil, fmt.Errorf("unknown projection %q (mercator|equirect)", o.Proj)
	}
	if len(o.GCPs) > 0 {
		var gs []GCP
		for _, s := range o.GCPs {
			g, err := ParseGCP(s)
			if err != nil {
				return nil, err
			}
			gs = append(gs, g)
		}
		return FromGCPs(gs, p)
	}
	if o.BBox != "" {
		bb, err := ParseBBox(o.BBox)
		if err != nil {
			return nil, err
		}
		return FromBBox(bb, w, h, p), nil
	}
	if o.Region != "" {
		bb, ok := Regions[strings.ToLower(o.Region)]
		if !ok {
			return nil, fmt.Errorf("unknown region %q (world|europe|russia|us|na|asia|latam)", o.Region)
		}
		return FromBBox(bb, w, h, p), nil
	}
	return nil, nil
}
