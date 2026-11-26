package backbone

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"image/color"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// affine is [a b c d e f]: x' = a x + c y + e, y' = b x + d y + f (SVG order).
type affine [6]float64

var identity = affine{1, 0, 0, 1, 0, 0}

func (m affine) mul(n affine) affine {
	return affine{m[0]*n[0] + m[2]*n[1], m[1]*n[0] + m[3]*n[1], m[0]*n[2] + m[2]*n[3], m[1]*n[2] + m[3]*n[3],
		m[0]*n[4] + m[2]*n[5] + m[4], m[1]*n[4] + m[3]*n[5] + m[5]}
}

func (m affine) apply(x, y float64) (float64, float64) {
	return m[0]*x + m[2]*y + m[4], m[1]*x + m[3]*y + m[5]
}

var trRe = regexp.MustCompile(`(matrix|translate|scale|rotate|skewX|skewY)\s*\(([^)]*)\)`)

func parseTransform(s string) affine {
	m := identity
	for _, t := range trRe.FindAllStringSubmatch(s, -1) {
		v := numbers(t[2])
		var n affine
		switch t[1] {
		case "matrix":
			if len(v) != 6 {
				continue
			}
			n = affine{v[0], v[1], v[2], v[3], v[4], v[5]}
		case "translate":
			if len(v) == 0 {
				continue
			}
			ty := 0.0
			if len(v) > 1 {
				ty = v[1]
			}
			n = affine{1, 0, 0, 1, v[0], ty}
		case "scale":
			if len(v) == 0 {
				continue
			}
			sy := v[0]
			if len(v) > 1 {
				sy = v[1]
			}
			n = affine{v[0], 0, 0, sy, 0, 0}
		case "rotate":
			if len(v) == 0 {
				continue
			}
			a := v[0] * math.Pi / 180
			n = affine{math.Cos(a), math.Sin(a), -math.Sin(a), math.Cos(a), 0, 0}
			if len(v) == 3 {
				n = affine{1, 0, 0, 1, v[1], v[2]}.mul(n).mul(affine{1, 0, 0, 1, -v[1], -v[2]})
			}
		case "skewX":
			if len(v) == 0 {
				continue
			}
			n = affine{1, 0, math.Tan(v[0] * math.Pi / 180), 1, 0, 0}
		case "skewY":
			if len(v) == 0 {
				continue
			}
			n = affine{1, math.Tan(v[0] * math.Pi / 180), 0, 1, 0, 0}
		}
		m = m.mul(n)
	}
	return m
}

var numRe = regexp.MustCompile(`[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?`)

func numbers(s string) []float64 {
	var out []float64
	for _, t := range numRe.FindAllString(s, -1) {
		if v, err := strconv.ParseFloat(t, 64); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// PathPolylines flattens an SVG path into polylines (curves are sampled).
func PathPolylines(d string) [][][2]float64 {
	var out [][][2]float64
	var cur [][2]float64
	var x, y, sx, sy, lcx, lcy float64
	var prev byte
	flush := func() {
		if len(cur) >= 2 {
			out = append(out, cur)
		}
		cur = nil
	}
	add := func(px, py float64) { cur = append(cur, [2]float64{px, py}) }
	i := 0
	var cmd byte
	readNums := func(n int) ([]float64, bool) {
		var v []float64
		for len(v) < n {
			for i < len(d) && (d[i] == ' ' || d[i] == ',' || d[i] == '\n' || d[i] == '\t' || d[i] == '\r') {
				i++
			}
			if i >= len(d) {
				return nil, false
			}
			loc := numRe.FindStringIndex(d[i:])
			if loc == nil || loc[0] != 0 {
				return nil, false
			}
			// arc flags may be glued: "a1 1 0 01 5 5"
			if cmd == 'a' || cmd == 'A' {
				if k := len(v); (k == 3 || k == 4) && (d[i] == '0' || d[i] == '1') {
					v = append(v, float64(d[i]-'0'))
					i++
					continue
				}
			}
			f, _ := strconv.ParseFloat(d[i:i+loc[1]], 64)
			v = append(v, f)
			i += loc[1]
		}
		return v, true
	}
	cubic := func(x1, y1, x2, y2, ex, ey float64) {
		x0, y0 := x, y
		for k := 1; k <= 8; k++ {
			t := float64(k) / 8
			mt := 1 - t
			add(mt*mt*mt*x0+3*mt*mt*t*x1+3*mt*t*t*x2+t*t*t*ex, mt*mt*mt*y0+3*mt*mt*t*y1+3*mt*t*t*y2+t*t*t*ey)
		}
		lcx, lcy, x, y = x2, y2, ex, ey
	}
	quad := func(x1, y1, ex, ey float64) {
		x0, y0 := x, y
		for k := 1; k <= 6; k++ {
			t := float64(k) / 6
			mt := 1 - t
			add(mt*mt*x0+2*mt*t*x1+t*t*ex, mt*mt*y0+2*mt*t*y1+t*t*ey)
		}
		lcx, lcy, x, y = x1, y1, ex, ey
	}
	for i < len(d) {
		c := d[i]
		if strings.IndexByte("MmLlHhVvCcSsQqTtAaZz", c) >= 0 {
			cmd = c
			i++
		} else if c == ' ' || c == ',' || c == '\n' || c == '\t' || c == '\r' {
			i++
			continue
		} else if cmd == 0 {
			return out
		}
		rel := cmd >= 'a'
		ox, oy := 0.0, 0.0
		if rel {
			ox, oy = x, y
		}
		switch cmd | 0x20 {
		case 'z':
			if len(cur) > 0 {
				add(sx, sy)
			}
			x, y = sx, sy
			flush()
			prev = 'z'
			continue
		case 'm':
			v, ok := readNums(2)
			if !ok {
				flush()
				return out
			}
			flush()
			x, y = ox+v[0], oy+v[1]
			sx, sy = x, y
			add(x, y)
			if rel {
				cmd = 'l'
			} else {
				cmd = 'L'
			}
		case 'l':
			v, ok := readNums(2)
			if !ok {
				break
			}
			x, y = ox+v[0], oy+v[1]
			add(x, y)
		case 'h':
			v, ok := readNums(1)
			if !ok {
				break
			}
			x = ox + v[0]
			add(x, y)
		case 'v':
			v, ok := readNums(1)
			if !ok {
				break
			}
			y = oy + v[0]
			add(x, y)
		case 'c':
			v, ok := readNums(6)
			if !ok {
				break
			}
			cubic(ox+v[0], oy+v[1], ox+v[2], oy+v[3], ox+v[4], oy+v[5])
		case 's':
			v, ok := readNums(4)
			if !ok {
				break
			}
			x1, y1 := x, y
			if p := prev | 0x20; p == 'c' || p == 's' {
				x1, y1 = 2*x-lcx, 2*y-lcy
			}
			cubic(x1, y1, ox+v[0], oy+v[1], ox+v[2], oy+v[3])
		case 'q':
			v, ok := readNums(4)
			if !ok {
				break
			}
			quad(ox+v[0], oy+v[1], ox+v[2], oy+v[3])
		case 't':
			v, ok := readNums(2)
			if !ok {
				break
			}
			x1, y1 := x, y
			if p := prev | 0x20; p == 'q' || p == 't' {
				x1, y1 = 2*x-lcx, 2*y-lcy
			}
			quad(x1, y1, ox+v[0], oy+v[1])
		case 'a':
			v, ok := readNums(7)
			if !ok {
				break
			}
			// arcs: endpoint plus a midpoint is enough at map scale
			ex, ey := ox+v[5], oy+v[6]
			add((x+ex)/2, (y+ey)/2)
			x, y = ex, ey
			add(x, y)
		}
		if len(cur) == 0 {
			add(x, y)
		}
		prev = cmd
		// avoid an endless loop on garbage
		if i < len(d) && strings.IndexByte("MmLlHhVvCcSsQqTtAaZz \t\r\n,", d[i]) < 0 && numRe.FindStringIndex(d[i:]) == nil {
			i++
		}
	}
	flush()
	return out
}

// svgShape is a stroked line or a marker found in the document.
type svgShape struct {
	kind   string // line|dot|text
	stroke string // normalized #rrggbb
	pts    [][2]float64
	r      float64
	text   string
}

type svgStyle struct {
	stroke, fill string
	m            affine
	hidden       bool
}

var cssRuleRe = regexp.MustCompile(`([^{}]+)\{([^}]*)\}`)

func styleProps(s string) map[string]string {
	out := map[string]string{}
	for _, d := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(d, ":")
		if ok {
			out[strings.TrimSpace(strings.ToLower(k))] = strings.TrimSpace(v)
		}
	}
	return out
}

var namedColors = map[string]string{"red": "#ff0000", "green": "#008000", "blue": "#0000ff", "black": "#000000", "white": "#ffffff",
	"orange": "#ffa500", "yellow": "#ffff00", "purple": "#800080", "magenta": "#ff00ff", "cyan": "#00ffff", "gray": "#808080",
	"grey": "#808080", "lime": "#00ff00", "navy": "#000080", "teal": "#008080", "maroon": "#800000", "darkred": "#8b0000",
	"darkblue": "#00008b", "darkgreen": "#006400", "crimson": "#dc143c", "gold": "#ffd700", "pink": "#ffc0cb"}

func normColor(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "none" || s == "transparent" || strings.HasPrefix(s, "url(") {
		return ""
	}
	if c, ok := namedColors[s]; ok {
		return c
	}
	if strings.HasPrefix(s, "rgb") {
		v := numbers(s)
		if len(v) >= 3 {
			return hexOf(color.RGBA{uint8(v[0]), uint8(v[1]), uint8(v[2]), 255})
		}
	}
	if c, err := ParseHexColor(s); err == nil {
		return hexOf(c)
	}
	return ""
}

// svgDoc is the flattened document.
type svgDoc struct {
	viewBox [4]float64
	shapes  []svgShape
}

func parseSVG(b []byte) (*svgDoc, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	doc := &svgDoc{}
	css := map[string]map[string]string{} // ".cls" / "tag" -> props
	stack := []svgStyle{{m: identity}}
	var textBuf *svgShape
	var textM affine
	textXY := false
	inStyle := false
	var styleText strings.Builder
	sawSVG := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if sawSVG && len(doc.shapes) > 0 {
				break
			}
			return nil, fmt.Errorf("svg: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			attr := map[string]string{}
			for _, a := range t.Attr {
				attr[strings.ToLower(a.Name.Local)] = a.Value
			}
			name := strings.ToLower(t.Name.Local)
			parent := stack[len(stack)-1]
			st := parent
			props := map[string]string{}
			for k, v := range css[name] {
				props[k] = v
			}
			for _, c := range strings.Fields(attr["class"]) {
				for k, v := range css["."+c] {
					props[k] = v
				}
			}
			for _, k := range []string{"stroke", "fill", "display", "visibility"} {
				if v, ok := attr[k]; ok {
					props[k] = v
				}
			}
			for k, v := range styleProps(attr["style"]) {
				props[k] = v
			}
			if v, ok := props["stroke"]; ok {
				st.stroke = normColor(v)
			}
			if v, ok := props["fill"]; ok {
				st.fill = normColor(v)
			}
			if props["display"] == "none" || props["visibility"] == "hidden" {
				st.hidden = true
			}
			if tr := attr["transform"]; tr != "" {
				st.m = parent.m.mul(parseTransform(tr))
			}
			stack = append(stack, st)
			f := func(k string) float64 {
				v, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(attr[k]), "px"), 64)
				return v
			}
			tp := func(pts [][2]float64) [][2]float64 {
				for i := range pts {
					pts[i][0], pts[i][1] = st.m.apply(pts[i][0], pts[i][1])
				}
				return pts
			}
			switch name {
			case "svg":
				if !sawSVG {
					sawSVG = true
					if v := numbers(attr["viewbox"]); len(v) == 4 && v[2] > 0 && v[3] > 0 {
						doc.viewBox = [4]float64{v[0], v[1], v[2], v[3]}
					} else if f("width") > 0 && f("height") > 0 {
						doc.viewBox = [4]float64{0, 0, f("width"), f("height")}
					}
				}
			case "style":
				inStyle = true
			case "path", "line", "polyline", "polygon":
				if st.hidden || st.stroke == "" {
					break
				}
				var lines [][][2]float64
				switch name {
				case "path":
					lines = PathPolylines(attr["d"])
				case "line":
					lines = [][][2]float64{{{f("x1"), f("y1")}, {f("x2"), f("y2")}}}
				default:
					v := numbers(attr["points"])
					var p [][2]float64
					for i := 0; i+1 < len(v); i += 2 {
						p = append(p, [2]float64{v[i], v[i+1]})
					}
					if name == "polygon" && len(p) > 0 {
						p = append(p, p[0])
					}
					lines = [][][2]float64{p}
				}
				for _, l := range lines {
					if len(l) >= 2 {
						doc.shapes = append(doc.shapes, svgShape{kind: "line", stroke: st.stroke, pts: tp(l)})
					}
				}
			case "circle", "ellipse":
				if st.hidden {
					break
				}
				r := f("r")
				if name == "ellipse" {
					r = (f("rx") + f("ry")) / 2
				}
				x, y := st.m.apply(f("cx"), f("cy"))
				col := st.fill
				if col == "" {
					col = st.stroke
				}
				doc.shapes = append(doc.shapes, svgShape{kind: "dot", stroke: col, pts: [][2]float64{{x, y}}, r: r * math.Sqrt(math.Abs(st.m[0]*st.m[3]-st.m[1]*st.m[2]))})
			case "text":
				if st.hidden {
					break
				}
				x, y := f("x"), f("y")
				if v := numbers(attr["x"]); len(v) > 0 {
					x = v[0]
				}
				if v := numbers(attr["y"]); len(v) > 0 {
					y = v[0]
				}
				textM, textXY = st.m, len(numbers(attr["x"])) > 0
				x, y = st.m.apply(x, y)
				textBuf = &svgShape{kind: "text", pts: [][2]float64{{x, y}}}
			case "tspan":
				// PDF exports put the position on the first tspan only
				if textBuf != nil && !textXY {
					xs, ys := numbers(attr["x"]), numbers(attr["y"])
					if len(xs) > 0 && len(ys) > 0 {
						x, y := textM.mul(parseTransform(attr["transform"])).apply(xs[0], ys[0])
						textBuf.pts[0] = [2]float64{x, y}
						textXY = true
					}
				}
			}
		case xml.EndElement:
			name := strings.ToLower(t.Name.Local)
			if name == "style" {
				inStyle = false
				for _, r := range cssRuleRe.FindAllStringSubmatch(styleText.String(), -1) {
					for _, sel := range strings.Split(r[1], ",") {
						sel = strings.TrimSpace(sel)
						if sel == "" {
							continue
						}
						if css[sel] == nil {
							css[sel] = map[string]string{}
						}
						for k, v := range styleProps(r[2]) {
							css[sel][k] = v
						}
					}
				}
				styleText.Reset()
			}
			if name == "text" && textBuf != nil {
				textBuf.text = strings.Join(strings.Fields(textBuf.text), " ")
				if textBuf.text != "" {
					doc.shapes = append(doc.shapes, *textBuf)
				}
				textBuf = nil
			}
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if inStyle {
				styleText.Write(t)
			} else if textBuf != nil {
				textBuf.text += string(t)
			}
		}
	}
	if !sawSVG {
		return nil, errors.New("svg: no <svg> element")
	}
	if doc.viewBox[2] == 0 {
		// no size: use the extent of the shapes
		x0, y0, x1, y1 := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
		for _, s := range doc.shapes {
			for _, p := range s.pts {
				x0, y0, x1, y1 = math.Min(x0, p[0]), math.Min(y0, p[1]), math.Max(x1, p[0]), math.Max(y1, p[1])
			}
		}
		if x1 > x0 && y1 > y0 {
			doc.viewBox = [4]float64{x0, y0, x1 - x0, y1 - y0}
		}
	}
	return doc, nil
}

// SVGOptions tune the vector engine.
type SVGOptions struct {
	Color   string  // stroke colour of the backbone; "" = the saturated stroke with the longest total length
	SnapPx  float64 // line ends join a marker this close (default 2% of the picture)
	Labels  bool    // use city labels as ground control points when no bbox/region is given
	Epsilon float64 // Douglas-Peucker tolerance in user units (default 0.1% of the width)
}

// ParseSVG extracts the backbone of an SVG map. ref may be nil: city labels
// are then used as control points (at least 3 must be known cities).
func ParseSVG(ctx context.Context, b []byte, ro RefOptions, o SVGOptions, gc *Geocoder) (*Graph, error) {
	doc, err := parseSVG(b)
	if err != nil {
		return nil, err
	}
	vb := doc.viewBox
	if vb[2] <= 0 {
		return nil, errors.New("svg: no viewBox / size and no shapes")
	}
	g := &Graph{ParsedBy: "svg"}
	// stroke colour of the backbone
	lengths := map[string]float64{}
	for _, s := range doc.shapes {
		if s.kind == "line" {
			lengths[s.stroke] += polyLen(s.pts)
		}
	}
	col := normColor(o.Color)
	if o.Color != "" && col == "" {
		return nil, fmt.Errorf("colour %q: want #rrggbb", o.Color)
	}
	if col == "" {
		type kv struct {
			c string
			l float64
		}
		var ks []kv
		for c, l := range lengths {
			cc, _ := ParseHexColor(c)
			s, v := satVal(float64(cc.R), float64(cc.G), float64(cc.B))
			if s >= 0.35 && v >= 0.25 {
				ks = append(ks, kv{c, l})
			}
		}
		sort.Slice(ks, func(i, j int) bool { return ks[i].l > ks[j].l || ks[i].l == ks[j].l && ks[i].c < ks[j].c })
		if len(ks) == 0 {
			for c, l := range lengths {
				ks = append(ks, kv{c, l})
			}
			sort.Slice(ks, func(i, j int) bool { return ks[i].l > ks[j].l })
		}
		if len(ks) == 0 {
			return nil, errors.New("svg: no stroked lines")
		}
		col = ks[0].c
		if len(ks) > 1 {
			var alt []string
			for _, k := range ks[1:min(len(ks), 4)] {
				alt = append(alt, k.c)
			}
			g.Notes = append(g.Notes, "line colour "+col+" (other candidates: "+strings.Join(alt, ", ")+"; --color to pick)")
		}
	}
	g.Color = col
	ref, err := ro.Build(int(math.Round(vb[2])), int(math.Round(vb[3])))
	if err != nil {
		return nil, err
	}
	if ref != nil {
		// Build works in pixels from 0,0: shift by the viewBox origin and scale
		base := ref
		sx, sy := 1.0, 1.0
		if r := math.Round(vb[2]); r > 0 {
			sx = r / vb[2]
		}
		if r := math.Round(vb[3]); r > 0 {
			sy = r / vb[3]
		}
		ref = &GeoRef{Proj: base.Proj, m: [6]float64{base.m[0] * sx, base.m[1] * sy, base.m[2] - base.m[0]*sx*vb[0] - base.m[1]*sy*vb[1],
			base.m[3] * sx, base.m[4] * sy, base.m[5] - base.m[3]*sx*vb[0] - base.m[4]*sy*vb[1]}}
	}
	// labels → known cities
	type label struct {
		x, y float64
		text string
		p    *Place
	}
	var labels []label
	for _, s := range doc.shapes {
		if s.kind == "text" {
			labels = append(labels, label{x: s.pts[0][0], y: s.pts[0][1], text: s.text})
		}
	}
	if ref == nil {
		off := &Geocoder{Offline: true, CachePath: gc.cachePath()}
		if gc != nil {
			off.PDB = gc.PDB
		}
		var gcps []GCP
		for i := range labels {
			if p := off.Lookup(ctx, labels[i].text, ""); p != nil {
				labels[i].p = p
				gcps = append(gcps, GCP{X: labels[i].x, Y: labels[i].y, Lon: p.Lon, Lat: p.Lat})
			}
		}
		ref, gcps, err = robustFit(gcps, ro.Proj)
		if err != nil {
			return nil, fmt.Errorf("svg: no geographic reference: give --region/--bbox/--gcp (%v)", err)
		}
		g.Notes = append(g.Notes, fmt.Sprintf("referenced by %d city labels", len(gcps)))
	}
	snap := o.SnapPx
	if snap <= 0 {
		snap = 0.02 * math.Max(vb[2], vb[3])
	}
	eps := o.Epsilon
	if eps <= 0 {
		eps = 0.001 * vb[2]
	}
	// markers: dots of the backbone colour, or any small dot when none match
	var dots [][2]float64
	for pass := 0; pass < 2 && len(dots) == 0; pass++ {
		for _, s := range doc.shapes {
			if s.kind == "dot" && s.r > 0 && s.r < 0.03*vb[2] && (pass == 1 || colorDist(hexRGBA(s.stroke), hexRGBA(col)) < 60) {
				dots = append(dots, s.pts[0])
			}
		}
	}
	type pnode struct {
		x, y float64
		id   string
	}
	var nodes []*pnode
	find := func(x, y float64, add bool) *pnode {
		var best *pnode
		bd := snap
		for _, n := range nodes {
			if d := math.Hypot(n.x-x, n.y-y); d <= bd {
				bd, best = d, n
			}
		}
		if best == nil && add {
			best = &pnode{x: x, y: y}
			nodes = append(nodes, best)
		}
		return best
	}
	for _, d := range dots {
		find(d[0], d[1], true)
	}
	dotsOnly := len(nodes) > 0
	type pline struct {
		pts  [][2]float64
		a, b *pnode
	}
	var lines []pline
	for _, s := range doc.shapes {
		if s.kind != "line" || colorDist(hexRGBA(s.stroke), hexRGBA(col)) > 30 {
			continue
		}
		pts := Simplify(s.pts, eps)
		if polyLen(pts) < snap/4 {
			continue
		}
		a := find(pts[0][0], pts[0][1], !dotsOnly)
		start := 0
		// one path through several markers: split at every marker it passes
		for i := 1; i < len(pts)-1 && dotsOnly; i++ {
			if m := find(pts[i][0], pts[i][1], false); m != nil && m != a {
				lines = append(lines, pline{append([][2]float64{}, pts[start:i+1]...), a, m})
				a, start = m, i
			}
		}
		b := find(pts[len(pts)-1][0], pts[len(pts)-1][1], !dotsOnly)
		lines = append(lines, pline{pts[start:], a, b})
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("svg: no lines of colour %s", col)
	}
	// name nodes after the nearest label
	used := map[*pnode]bool{}
	for _, l := range lines {
		used[l.a], used[l.b] = true, true
	}
	n := 0
	for _, pn := range nodes {
		if !used[pn] && !dotsOnly {
			continue
		}
		name, bd := "", 3*snap
		for _, lb := range labels {
			if d := math.Hypot(lb.x-pn.x, lb.y-pn.y); d < bd {
				bd, name = d, lb.text
			}
		}
		lon, lat := ref.LonLat(pn.x, pn.y)
		lon = wrapLon(lon)
		n++
		pn.id = fmt.Sprintf("p%d", n)
		if name != "" && g.nodeByName(name) == nil {
			pn.id = nodeID(name)
			if pn.id == "" || g.node(pn.id) != nil {
				pn.id = fmt.Sprintf("p%d", n)
			}
		} else if c := Nearest(lat, lon, 40); c != nil && name == "" {
			name = c.Name
		}
		g.Nodes = append(g.Nodes, Node{ID: pn.id, Name: name, Lat: lat, Lon: lon, Geo: "image"})
	}
	for _, l := range lines {
		var coords [][2]float64
		for _, p := range l.pts {
			lon, lat := ref.LonLat(p[0], p[1])
			coords = append(coords, [2]float64{lon, lat})
		}
		lk := Link{Coords: shiftLine(coords)}
		if l.a != nil {
			lk.From = l.a.id
		}
		if l.b != nil {
			lk.To = l.b.id
		}
		g.Links = append(g.Links, lk)
	}
	return g, g.Validate()
}

func (g *Graph) nodeByName(name string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].Name == name {
			return &g.Nodes[i]
		}
	}
	return nil
}

func hexRGBA(s string) color.RGBA { c, _ := ParseHexColor(s); return c }

func (g *Geocoder) cachePath() string {
	if g == nil {
		return ""
	}
	return g.CachePath
}

// robustFit fits control points and drops outliers (labels of other things
// that happen to be city names) until the residuals are consistent.
func robustFit(gcps []GCP, proj string) (*GeoRef, []GCP, error) {
	p := Mercator
	if strings.HasPrefix(strings.ToLower(proj), "equi") {
		p = Equirect
	}
	if len(gcps) < 3 {
		return nil, nil, fmt.Errorf("only %d city labels recognised, need 3", len(gcps))
	}
	// maps centred on the Pacific: longitudes west of some meridian are
	// continued past 180°; try a few cut meridians and keep the best fit
	var best *GeoRef
	var bestG []GCP
	var bestErr error
	for _, cut := range []float64{-999, -30, 0, 30, 60, -60, -90, -120, 90, 120, 150} {
		gs := make([]GCP, len(gcps))
		copy(gs, gcps)
		for i := range gs {
			if gs[i].Lon < cut {
				gs[i].Lon += 360
			}
		}
		r, kept, err := fitDropOutliers(gs, p)
		if err != nil {
			bestErr = err
			continue
		}
		if best == nil || len(kept) > len(bestG) {
			best, bestG = r, kept
		}
	}
	if best == nil {
		return nil, nil, bestErr
	}
	return best, bestG, nil
}

func fitDropOutliers(gcps []GCP, p Projection) (*GeoRef, []GCP, error) {
	for len(gcps) >= 3 {
		r, err := FromGCPs(gcps, p)
		if err != nil {
			return nil, nil, err
		}
		worst, wi := 0.0, -1
		for i, c := range gcps {
			lon, lat := r.LonLat(c.X, c.Y)
			if d := haversine(lat, lon, c.Lat, c.Lon); d > worst {
				worst, wi = d, i
			}
		}
		if worst < 150 {
			return r, gcps, nil
		}
		gcps = append(gcps[:wi], gcps[wi+1:]...)
	}
	return nil, nil, errors.New("city labels do not agree on a map projection")
}

func wrapLon(lon float64) float64 {
	for lon > 180 {
		lon -= 360
	}
	for lon < -180 {
		lon += 360
	}
	return lon
}

// shiftLine moves a polyline by whole turns so it starts in [-180,180]; it
// stays continuous (a line crossing the antimeridian keeps |lon| > 180).
func shiftLine(c [][2]float64) [][2]float64 {
	if len(c) == 0 {
		return c
	}
	d := wrapLon(c[0][0]) - c[0][0]
	for i := range c {
		c[i][0] += d
	}
	return c
}
