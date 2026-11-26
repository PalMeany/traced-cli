package backbone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options of one parse.
type Options struct {
	Provider string
	ASN      int
	Engine   string // auto|llm|cv|svg
	Source   string // recorded in the layer (file name / URL)
	Ref      RefOptions
	CV       CVOptions
	SVG      SVGOptions
	Vision   *VisionConfig // nil = no LLM
	Geocoder *Geocoder
}

// MaxInput is the largest picture accepted.
const MaxInput = 25 << 20

// IsSVG sniffs SVG content.
func IsSVG(b []byte, name string) bool {
	if strings.EqualFold(filepath.Ext(name), ".svg") || strings.HasSuffix(strings.ToLower(name), ".svgz") {
		return true
	}
	head := b
	if len(head) > 2048 {
		head = head[:2048]
	}
	return bytes.Contains(bytes.ToLower(head), []byte("<svg"))
}

// Mime of a picture.
func Mime(b []byte, name string) string {
	if IsSVG(b, name) {
		return "image/svg+xml"
	}
	if len(b) > 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP" {
		return "image/webp"
	}
	ct := http.DetectContentType(b)
	if strings.HasPrefix(ct, "image/") {
		return ct
	}
	return "application/octet-stream"
}

// Load reads a file or downloads an http(s) URL.
func Load(ctx context.Context, src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		req, err := http.NewRequestWithContext(ctx, "GET", src, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; traced/"+Version+"; +https://github.com/PalMeany/traced-cli)")
		cl := &http.Client{Timeout: 2 * time.Minute}
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s: HTTP %d", src, resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxInput+1))
		if err != nil {
			return nil, err
		}
		if len(b) > MaxInput {
			return nil, fmt.Errorf("%s: larger than %d MB", src, MaxInput>>20)
		}
		return b, nil
	}
	st, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxInput {
		return nil, fmt.Errorf("%s: larger than %d MB", src, MaxInput>>20)
	}
	return os.ReadFile(src)
}

// EngineFor resolves "auto".
func EngineFor(engine string, svg bool, vision *VisionConfig) (string, error) {
	switch engine {
	case "", "auto":
		if svg {
			return "svg", nil
		}
		if vision != nil {
			return "llm", nil
		}
		return "cv", nil
	case "llm":
		if vision == nil {
			return "", errors.New("llm engine: set TRACED_VISION_API_KEY (OpenAI compatible) or GEMINI_API_KEY")
		}
		return "llm", nil
	case "cv":
		if svg {
			return "", errors.New("cv engine reads raster pictures; use --engine svg for SVG")
		}
		return "cv", nil
	case "svg":
		if !svg {
			return "", errors.New("svg engine: the input is not SVG")
		}
		return "svg", nil
	}
	return "", fmt.Errorf("unknown engine %q (auto|llm|cv|svg)", engine)
}

// Parse extracts a backbone graph from picture bytes.
func Parse(ctx context.Context, b []byte, o Options) (*Graph, error) {
	if o.Provider == "" {
		return nil, errors.New("provider name required (--provider)")
	}
	if o.Geocoder == nil {
		o.Geocoder = &Geocoder{}
	}
	svg := IsSVG(b, o.Source)
	eng, err := EngineFor(o.Engine, svg, o.Vision)
	if err != nil {
		return nil, err
	}
	var g *Graph
	switch eng {
	case "svg":
		g, err = ParseSVG(ctx, b, o.Ref, o.SVG, o.Geocoder)
	case "llm":
		var a *VisionAnswer
		a, err = o.Vision.Ask(ctx, b, Mime(b, o.Source), o.Provider)
		if err == nil {
			g = GraphFromAnswer(ctx, a, o.Geocoder)
			g.ParsedBy = o.Vision.Name()
			_ = o.Geocoder.Save()
			err = g.Validate()
		}
	case "cv":
		g, err = ParseRaster(b, o.Ref, o.CV)
	}
	if err != nil {
		return nil, err
	}
	g.Provider, g.ASN = o.Provider, o.ASN
	if g.Source == "" {
		g.Source = o.Source
	}
	return g, nil
}

// ParseRaster runs the CV engine on a PNG/JPEG/WebP picture.
func ParseRaster(b []byte, ro RefOptions, o CVOptions) (*Graph, error) {
	lim := o.MaxPixels
	if lim <= 0 {
		lim = MaxPixels
	}
	img, _, err := DecodeImageLimit(b, lim)
	if err != nil {
		return nil, err
	}
	bd := img.Bounds()
	ref, err := ro.Build(bd.Dx(), bd.Dy())
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, errors.New("cv engine needs a geographic reference: --region world|europe|russia|us|asia, --bbox minLon,minLat,maxLon,maxLat or --gcp px,py=lon,lat (×2+)")
	}
	v, err := Vectorize(img, o)
	if err != nil {
		return nil, err
	}
	o.defaults()
	g := &Graph{ParsedBy: "cv", Color: v.Color}
	if len(v.Candidates) > 1 {
		var alt []string
		for _, c := range v.Candidates[1:] {
			alt = append(alt, c.Color)
		}
		g.Notes = append(g.Notes, "line colour "+v.Color+" auto-detected (other candidates: "+strings.Join(alt, ", ")+"; --color to pick)")
	}
	ids := make([]string, len(v.Nodes))
	seen := map[string]bool{}
	for i, n := range v.Nodes {
		lon, lat := ref.LonLat(n.X, n.Y)
		id := fmt.Sprintf("p%d", i+1)
		name := ""
		if o.SnapKm > 0 && n.Deg != 2 {
			if c := Nearest(lat, lon, o.SnapKm); c != nil {
				name = c.Name
				if k := nodeID(c.Name); !seen[k] {
					id = k
				}
			}
		}
		seen[id] = true
		ids[i] = id
		g.Nodes = append(g.Nodes, Node{ID: id, Name: name, Lat: lat, Lon: lon, Geo: "image"})
	}
	for _, l := range v.Lines {
		var coords [][2]float64
		for _, p := range l.Pts {
			lon, lat := ref.LonLat(p[0], p[1])
			coords = append(coords, [2]float64{lon, lat})
		}
		from, to := "", ""
		if l.StartEnd[0] >= 0 {
			from = ids[l.StartEnd[0]]
		}
		if l.StartEnd[1] >= 0 {
			to = ids[l.StartEnd[1]]
		}
		// a bend right at a known hub is a PoP without its own marker: split there
		start := 0
		for i := 1; i < len(coords)-1 && o.SnapKm > 0; i++ {
			c := Nearest(coords[i][1], coords[i][0], o.SnapKm/2)
			if c == nil {
				continue
			}
			id := nodeID(c.Name)
			if g.node(id) == nil {
				g.Nodes = append(g.Nodes, Node{ID: id, Name: c.Name, Lat: coords[i][1], Lon: coords[i][0], Geo: "image"})
				seen[id] = true
			}
			g.Links = append(g.Links, Link{From: from, To: id, Coords: append([][2]float64{}, coords[start:i+1]...)})
			from, start = id, i
		}
		g.Links = append(g.Links, Link{From: from, To: to, Coords: coords[start:]})
	}
	return g, g.Validate()
}
