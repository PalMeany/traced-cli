package backbone

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"sort"
	"strconv"
	"strings"

	_ "golang.org/x/image/webp"
)

// CVOptions tune the raster engine.
type CVOptions struct {
	Color     string  // "#rrggbb" of the backbone lines; "" = auto-detect
	Tolerance float64 // RGB distance accepted around Color (default 70)
	MaxSide   int     // pictures are downscaled to this many pixels (default 2400)
	MaxPixels int     // larger pictures are refused (default MaxPixels)
	MinLength float64 // polylines shorter than this (px) are dropped (default 12)
	Epsilon   float64 // Douglas-Peucker tolerance in px (default 1.5)
	SnapKm    float64 // name nodes after a known hub this close (default 40, <0 off)
}

func (o *CVOptions) defaults() {
	if o.Tolerance <= 0 {
		o.Tolerance = 70
	}
	if o.MaxSide <= 0 {
		o.MaxSide = 2400
	}
	if o.MinLength <= 0 {
		o.MinLength = 12
	}
	if o.Epsilon <= 0 {
		o.Epsilon = 1.5
	}
	if o.SnapKm == 0 {
		o.SnapKm = 40
	}
}

// ParseHexColor reads #rgb / #rrggbb.
func ParseHexColor(s string) (color.RGBA, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "#")
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) != 6 {
		return color.RGBA{}, fmt.Errorf("colour %q: want #rrggbb", s)
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return color.RGBA{}, fmt.Errorf("colour %q: want #rrggbb", s)
	}
	return color.RGBA{uint8(v >> 16), uint8(v >> 8), uint8(v), 255}, nil
}

func hexOf(c color.RGBA) string { return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B) }

// MaxPixels caps decoded pictures (memory: 4 bytes per pixel and more).
var MaxPixels = 60_000_000

// DecodeImage decodes PNG/JPEG/GIF/WebP.
func DecodeImage(b []byte) (image.Image, string, error) {
	return DecodeImageLimit(b, MaxPixels)
}

// DecodeImageLimit decodes a picture of at most maxPixels pixels.
func DecodeImageLimit(b []byte, maxPixels int) (image.Image, string, error) {
	cfg, f, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, "", fmt.Errorf("image: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxPixels {
		return nil, "", fmt.Errorf("image %dx%d is too large (limit %d Mpx)", cfg.Width, cfg.Height, maxPixels/1_000_000)
	}
	img, f, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, f, fmt.Errorf("image: %w", err)
	}
	return img, f, nil
}

// rgb is a flat RGB raster.
type rgb struct {
	w, h int
	pix  []uint8 // 3 bytes per pixel
}

// toRGB flattens (alpha over white) and box-downscales to maxSide.
func toRGB(img image.Image, maxSide int) (*rgb, int) {
	b := img.Bounds()
	W, H := b.Dx(), b.Dy()
	k := 1
	for (W+k-1)/k > maxSide || (H+k-1)/k > maxSide {
		k++
	}
	w, h := (W+k-1)/k, (H+k-1)/k
	out := &rgb{w: w, h: h, pix: make([]uint8, w*h*3)}
	acc := make([]uint32, w*h*4)
	for y := 0; y < H; y++ {
		for x := 0; x < W; x++ {
			r, g, bl, a := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			// premultiplied over white
			wh := 0xffff - a
			i := ((y/k)*w + x/k) * 4
			acc[i] += (r + wh) >> 8
			acc[i+1] += (g + wh) >> 8
			acc[i+2] += (bl + wh) >> 8
			acc[i+3]++
		}
	}
	for i := 0; i < w*h; i++ {
		n := acc[i*4+3]
		if n == 0 {
			continue
		}
		out.pix[i*3], out.pix[i*3+1], out.pix[i*3+2] = uint8(acc[i*4]/n), uint8(acc[i*4+1]/n), uint8(acc[i*4+2]/n)
	}
	return out, k
}

func (r *rgb) at(i int) (float64, float64, float64) {
	return float64(r.pix[i*3]), float64(r.pix[i*3+1]), float64(r.pix[i*3+2])
}

func satVal(R, G, B float64) (float64, float64) {
	mx := math.Max(R, math.Max(G, B))
	mn := math.Min(R, math.Min(G, B))
	if mx == 0 {
		return 0, 0
	}
	return (mx - mn) / mx, mx / 255
}

// ColorCandidate is a saturated colour that forms thin structures.
type ColorCandidate struct {
	Color string  `json:"color"`
	Share float64 `json:"share"` // of all pixels
	Thin  float64 `json:"thin"`  // boundary pixels / pixels (1 = hairlines)
	Score float64 `json:"score"`
}

// DetectLineColors ranks the saturated colours of the picture by how much
// they look like lines (many pixels, but thin) rather than fills or text.
func DetectLineColors(img image.Image, maxSide int) []ColorCandidate {
	if maxSide <= 0 {
		maxSide = 1200
	}
	r, _ := toRGB(img, maxSide)
	n := r.w * r.h
	bin := make([]int16, n)
	cnt := map[int16]int{}
	for i := 0; i < n; i++ {
		R, G, B := r.at(i)
		s, v := satVal(R, G, B)
		if s < 0.4 || v < 0.3 {
			bin[i] = -1
			continue
		}
		k := int16(int(R)>>5<<6 | int(G)>>5<<3 | int(B)>>5)
		bin[i] = k
		cnt[k]++
	}
	type acc struct{ n, edge, r, g, b int }
	st := map[int16]*acc{}
	for y := 0; y < r.h; y++ {
		for x := 0; x < r.w; x++ {
			i := y*r.w + x
			k := bin[i]
			if k < 0 || cnt[k] < n/20000+20 {
				continue
			}
			a := st[k]
			if a == nil {
				a = &acc{}
				st[k] = a
			}
			a.n++
			R, G, B := r.at(i)
			a.r += int(R)
			a.g += int(G)
			a.b += int(B)
			if x == 0 || y == 0 || x == r.w-1 || y == r.h-1 || bin[i-1] != k || bin[i+1] != k || bin[i-r.w] != k || bin[i+r.w] != k {
				a.edge++
			}
		}
	}
	var out []ColorCandidate
	for _, a := range st {
		share := float64(a.n) / float64(n)
		if share > 0.25 {
			continue // sea / land fill
		}
		thin := float64(a.edge) / float64(a.n)
		c := color.RGBA{uint8(a.r / a.n), uint8(a.g / a.n), uint8(a.b / a.n), 255}
		out = append(out, ColorCandidate{Color: hexOf(c), Share: math.Round(share*1e5) / 1e5, Thin: math.Round(thin*100) / 100,
			Score: float64(a.n) * thin * thin})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	// merge near-identical colours (neighbouring bins of one antialiased line)
	var merged []ColorCandidate
	for _, c := range out {
		cc, _ := ParseHexColor(c.Color)
		dup := false
		for _, m := range merged {
			mc, _ := ParseHexColor(m.Color)
			if colorDist(cc, mc) < 45 {
				dup = true
				break
			}
		}
		if !dup {
			merged = append(merged, c)
		}
		if len(merged) >= 6 {
			break
		}
	}
	return merged
}

func colorDist(a, b color.RGBA) float64 {
	dr, dg, db := float64(a.R)-float64(b.R), float64(a.G)-float64(b.G), float64(a.B)-float64(b.B)
	// weighted ("redmean") distance: closer to perceived difference than plain RGB
	rm := (float64(a.R) + float64(b.R)) / 2
	return math.Sqrt((2+rm/256)*dr*dr+4*dg*dg+(2+(255-rm)/256)*db*db) / 3
}

// mask marks pixels close to the target colour.
func mask(r *rgb, c color.RGBA, tol float64) []bool {
	m := make([]bool, r.w*r.h)
	for i := range m {
		R, G, B := r.at(i)
		m[i] = colorDist(color.RGBA{uint8(R), uint8(G), uint8(B), 255}, c) <= tol
	}
	return m
}

// close1 bridges one-pixel gaps (dilate then erode, 3×3).
func close1(m []bool, w, h int) []bool {
	d := make([]bool, len(m))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !m[y*w+x] {
				continue
			}
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					if xx, yy := x+dx, y+dy; xx >= 0 && yy >= 0 && xx < w && yy < h {
						d[yy*w+xx] = true
					}
				}
			}
		}
	}
	e := make([]bool, len(m))
	for y := 1; y < h-1; y++ {
		for x := 1; x < w-1; x++ {
			all := true
			for dy := -1; dy <= 1 && all; dy++ {
				for dx := -1; dx <= 1; dx++ {
					if !d[(y+dy)*w+x+dx] {
						all = false
						break
					}
				}
			}
			e[y*w+x] = all || m[y*w+x]
		}
	}
	return e
}

// Thin is the Zhang-Suen thinning of a binary raster (in place).
func Thin(m []bool, w, h int) {
	at := func(x, y int) bool {
		if x < 0 || y < 0 || x >= w || y >= h {
			return false
		}
		return m[y*w+x]
	}
	var del []int
	for {
		changed := false
		for pass := 0; pass < 2; pass++ {
			del = del[:0]
			for y := 0; y < h; y++ {
				for x := 0; x < w; x++ {
					if !m[y*w+x] {
						continue
					}
					// P2..P9 clockwise from north
					p := [8]bool{at(x, y-1), at(x+1, y-1), at(x+1, y), at(x+1, y+1), at(x, y+1), at(x-1, y+1), at(x-1, y), at(x-1, y-1)}
					b := 0
					for _, v := range p {
						if v {
							b++
						}
					}
					if b < 2 || b > 6 {
						continue
					}
					a := 0
					for i := 0; i < 8; i++ {
						if !p[i] && p[(i+1)%8] {
							a++
						}
					}
					if a != 1 {
						continue
					}
					if pass == 0 {
						if p[0] && p[2] && p[4] || p[2] && p[4] && p[6] {
							continue
						}
					} else if p[0] && p[2] && p[6] || p[0] && p[4] && p[6] {
						continue
					}
					del = append(del, y*w+x)
				}
			}
			for _, i := range del {
				m[i] = false
			}
			if len(del) > 0 {
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

// Polyline is a traced skeleton branch in pixel coordinates.
type Polyline struct {
	Pts      [][2]float64
	StartEnd [2]int // node index at each end
}

// PixelNode is a junction or end point of the skeleton.
type PixelNode struct {
	X, Y float64
	Deg  int
}

var nb8 = [8][2]int{{0, -1}, {1, -1}, {1, 0}, {1, 1}, {0, 1}, {-1, 1}, {-1, 0}, {-1, -1}}

// TraceSkeleton turns a one-pixel skeleton into nodes (junction clusters and
// end points) and the polylines between them.
func TraceSkeleton(m []bool, w, h int) ([]PixelNode, []Polyline) {
	at := func(x, y int) bool { return x >= 0 && y >= 0 && x < w && y < h && m[y*w+x] }
	// deg classifies a skeleton pixel: 2 = path, anything else = node. The
	// crossing number (0→1 transitions around the pixel) is used instead of
	// the neighbour count so that staircase corners stay path pixels.
	deg := func(x, y int) int {
		n, cn := 0, 0
		for i, d := range nb8 {
			if at(x+d[0], y+d[1]) {
				n++
			}
			e := nb8[(i+1)%8]
			if !at(x+d[0], y+d[1]) && at(x+e[0], y+e[1]) {
				cn++
			}
		}
		if n <= 1 {
			return n
		}
		if cn == 1 && n == 2 { // two touching neighbours: end of a line
			return 1
		}
		if cn <= 2 {
			return 2
		}
		return cn
	}
	// node pixels: degree != 2; adjacent node pixels form one node
	nodeOf := make([]int32, w*h)
	for i := range nodeOf {
		nodeOf[i] = -1
	}
	var nodes []PixelNode
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !m[y*w+x] || nodeOf[y*w+x] >= 0 || deg(x, y) == 2 {
				continue
			}
			id := int32(len(nodes))
			stack := [][2]int{{x, y}}
			nodeOf[y*w+x] = id
			var sx, sy, c float64
			for len(stack) > 0 {
				p := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				sx, sy, c = sx+float64(p[0]), sy+float64(p[1]), c+1
				for _, d := range nb8 {
					xx, yy := p[0]+d[0], p[1]+d[1]
					if at(xx, yy) && nodeOf[yy*w+xx] < 0 && deg(xx, yy) != 2 {
						nodeOf[yy*w+xx] = id
						stack = append(stack, [2]int{xx, yy})
					}
				}
			}
			nodes = append(nodes, PixelNode{X: sx / c, Y: sy / c})
		}
	}
	visited := make([]bool, w*h) // path (degree-2) pixels already used
	var lines []Polyline
	walk := func(start int32, sx, sy, x, y int) {
		pts := [][2]float64{{nodes[start].X, nodes[start].Y}}
		px, py := sx, sy
		for {
			i := y*w + x
			if nodeOf[i] >= 0 {
				pts = append(pts, [2]float64{nodes[nodeOf[i]].X, nodes[nodeOf[i]].Y})
				lines = append(lines, Polyline{Pts: pts, StartEnd: [2]int{int(start), int(nodeOf[i])}})
				return
			}
			if visited[i] {
				return
			}
			visited[i] = true
			pts = append(pts, [2]float64{float64(x), float64(y)})
			nx, ny, found := -1, -1, false
			// prefer an unvisited path pixel, then a node pixel (not the one we came from)
			for _, d := range nb8 {
				xx, yy := x+d[0], y+d[1]
				if !at(xx, yy) || xx == px && yy == py {
					continue
				}
				j := yy*w + xx
				if nodeOf[j] >= 0 {
					if nodeOf[j] == start && len(pts) < 3 {
						continue
					}
					nx, ny, found = xx, yy, true
					break
				}
				if !visited[j] && !found {
					nx, ny, found = xx, yy, true
				}
			}
			if !found {
				// the last pixels may touch a junction only through pixels
				// another walk took: join the nearest node pixel within 3 px
				end, bd := int32(-1), 10.0
				for dy := -3; dy <= 3; dy++ {
					for dx := -3; dx <= 3; dx++ {
						xx, yy := x+dx, y+dy
						if at(xx, yy) && nodeOf[yy*w+xx] >= 0 && (nodeOf[yy*w+xx] != start || len(pts) > 8) {
							if d := float64(dx*dx + dy*dy); d < bd {
								bd, end = d, nodeOf[yy*w+xx]
							}
						}
					}
				}
				if end >= 0 {
					pts = append(pts, [2]float64{nodes[end].X, nodes[end].Y})
				}
				lines = append(lines, Polyline{Pts: pts, StartEnd: [2]int{int(start), int(end)}})
				return
			}
			px, py, x, y = x, y, nx, ny
		}
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			id := nodeOf[y*w+x]
			if id < 0 {
				continue
			}
			for _, d := range nb8 {
				xx, yy := x+d[0], y+d[1]
				if at(xx, yy) && nodeOf[yy*w+xx] < 0 && !visited[yy*w+xx] {
					walk(id, x, y, xx, yy)
				}
			}
		}
	}
	// pure loops without any node
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if m[y*w+x] && nodeOf[y*w+x] < 0 && !visited[y*w+x] {
				id := int32(len(nodes))
				nodes = append(nodes, PixelNode{X: float64(x), Y: float64(y)})
				nodeOf[y*w+x] = id
				for _, d := range nb8 {
					xx, yy := x+d[0], y+d[1]
					if at(xx, yy) && nodeOf[yy*w+xx] < 0 && !visited[yy*w+xx] {
						walk(id, x, y, xx, yy)
						break
					}
				}
			}
		}
	}
	for _, l := range lines {
		for _, e := range l.StartEnd {
			if e >= 0 {
				nodes[e].Deg++
			}
		}
	}
	return nodes, lines
}

// Simplify is Douglas-Peucker.
func Simplify(pts [][2]float64, eps float64) [][2]float64 {
	if len(pts) < 3 {
		return pts
	}
	keep := make([]bool, len(pts))
	keep[0], keep[len(pts)-1] = true, true
	var rec func(a, b int)
	rec = func(a, b int) {
		dmax, idx := 0.0, -1
		ax, ay, bx, by := pts[a][0], pts[a][1], pts[b][0], pts[b][1]
		dx, dy := bx-ax, by-ay
		l := math.Hypot(dx, dy)
		for i := a + 1; i < b; i++ {
			var d float64
			if l == 0 {
				d = math.Hypot(pts[i][0]-ax, pts[i][1]-ay)
			} else {
				d = math.Abs(dy*pts[i][0]-dx*pts[i][1]+bx*ay-by*ax) / l
			}
			if d > dmax {
				dmax, idx = d, i
			}
		}
		if dmax > eps && idx > 0 {
			keep[idx] = true
			rec(a, idx)
			rec(idx, b)
		}
	}
	rec(0, len(pts)-1)
	out := make([][2]float64, 0, len(pts))
	for i, k := range keep {
		if k {
			out = append(out, pts[i])
		}
	}
	return out
}

func polyLen(p [][2]float64) float64 {
	s := 0.0
	for i := 1; i < len(p); i++ {
		s += math.Hypot(p[i][0]-p[i-1][0], p[i][1]-p[i-1][1])
	}
	return s
}

// VectorizeResult is the pixel-space outcome of the raster engine.
type VectorizeResult struct {
	Color      string
	Candidates []ColorCandidate
	Scale      int // downscale factor applied
	W, H       int // working raster size
	Nodes      []PixelNode
	Lines      []Polyline
}

// Vectorize runs mask → close → thin → trace → prune → simplify. Pixel
// coordinates in the result are in the original picture's scale.
func Vectorize(img image.Image, o CVOptions) (*VectorizeResult, error) {
	o.defaults()
	res := &VectorizeResult{}
	var target color.RGBA
	if o.Color != "" {
		c, err := ParseHexColor(o.Color)
		if err != nil {
			return nil, err
		}
		target = c
	} else {
		res.Candidates = DetectLineColors(img, 1200)
		if len(res.Candidates) == 0 {
			return nil, errors.New("no coloured lines found; pass --color #rrggbb")
		}
		target, _ = ParseHexColor(res.Candidates[0].Color)
	}
	res.Color = hexOf(target)
	r, k := toRGB(img, o.MaxSide)
	res.Scale, res.W, res.H = k, r.w, r.h
	m := close1(mask(r, target, o.Tolerance), r.w, r.h)
	removeSpecks(m, r.w, r.h, o.MinLength/float64(k))
	Thin(m, r.w, r.h)
	nodes, lines := TraceSkeleton(m, r.w, r.h)
	minLen := o.MinLength / float64(k)
	// prune short spurs (a dangling end) and tiny isolated strokes (text)
	var kept []Polyline
	for _, l := range lines {
		ln := polyLen(l.Pts)
		dangling := l.StartEnd[1] < 0 || nodes[l.StartEnd[0]].Deg == 1 || nodes[l.StartEnd[1]].Deg == 1
		if ln < minLen && dangling || ln < 2 {
			continue
		}
		kept = append(kept, l)
	}
	kept = mergeChains(kept, len(nodes))
	// tiny loops at a junction
	k2 := kept[:0]
	for _, l := range kept {
		if !(l.StartEnd[0] == l.StartEnd[1] && polyLen(l.Pts) < 4*minLen) {
			k2 = append(k2, l)
		}
	}
	kept = k2
	refineJunctions(nodes, kept)
	// renumber the nodes still used
	used := map[int]int{}
	for i := range kept {
		for j, e := range kept[i].StartEnd {
			if e < 0 {
				continue
			}
			if _, ok := used[e]; !ok {
				used[e] = len(res.Nodes)
				n := nodes[e]
				res.Nodes = append(res.Nodes, PixelNode{X: n.X * float64(k), Y: n.Y * float64(k)})
			}
			kept[i].StartEnd[j] = used[e]
			res.Nodes[used[e]].Deg++
		}
		pts := Simplify(kept[i].Pts, o.Epsilon)
		for j := range pts {
			pts[j] = [2]float64{pts[j][0] * float64(k), pts[j][1] * float64(k)}
		}
		kept[i].Pts = pts
	}
	res.Lines = kept
	if len(res.Lines) == 0 {
		return res, fmt.Errorf("no lines of colour %s found (try --color or --tolerance)", res.Color)
	}
	return res, nil
}

// removeSpecks drops connected components smaller than minExtent in both
// directions (labels, legend dots).
func removeSpecks(m []bool, w, h int, minExtent float64) {
	seen := make([]bool, len(m))
	var comp []int
	for s := range m {
		if !m[s] || seen[s] {
			continue
		}
		comp = comp[:0]
		stack := []int{s}
		seen[s] = true
		x0, y0, x1, y1 := w, h, 0, 0
		for len(stack) > 0 {
			i := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			comp = append(comp, i)
			x, y := i%w, i/w
			x0, y0, x1, y1 = min(x0, x), min(y0, y), max(x1, x), max(y1, y)
			for _, d := range nb8 {
				xx, yy := x+d[0], y+d[1]
				if xx >= 0 && yy >= 0 && xx < w && yy < h && m[yy*w+xx] && !seen[yy*w+xx] {
					seen[yy*w+xx] = true
					stack = append(stack, yy*w+xx)
				}
			}
		}
		if float64(max(x1-x0, y1-y0)) < minExtent*2 {
			for _, i := range comp {
				m[i] = false
			}
		}
	}
}

// mergeChains joins polylines meeting at a node of degree 2 (left over by
// spur pruning or staircase pixels) until only real ends and junctions stay.
func mergeChains(ls []Polyline, nNodes int) []Polyline {
	for {
		inc := make([][]int, nNodes)
		for i, l := range ls {
			for _, e := range l.StartEnd {
				if e >= 0 {
					inc[e] = append(inc[e], i)
				}
			}
		}
		merged := false
		for n := range inc {
			if len(inc[n]) != 2 || inc[n][0] == inc[n][1] {
				continue
			}
			a, b := ls[inc[n][0]], ls[inc[n][1]]
			// orient a to end at n and b to start at n
			if a.StartEnd[0] == n {
				a = reversed(a)
			}
			if b.StartEnd[1] == n && b.StartEnd[0] != n {
				b = reversed(b)
			}
			if a.StartEnd[1] != n || b.StartEnd[0] != n {
				continue
			}
			j := Polyline{Pts: append(append([][2]float64{}, a.Pts...), b.Pts[1:]...), StartEnd: [2]int{a.StartEnd[0], b.StartEnd[1]}}
			i0, i1 := inc[n][0], inc[n][1]
			ls[i0] = j
			ls = append(ls[:i1], ls[i1+1:]...)
			merged = true
			break
		}
		if !merged {
			return ls
		}
	}
}

func reversed(l Polyline) Polyline {
	p := make([][2]float64, len(l.Pts))
	for i := range l.Pts {
		p[len(p)-1-i] = l.Pts[i]
	}
	return Polyline{Pts: p, StartEnd: [2]int{l.StartEnd[1], l.StartEnd[0]}}
}

// refineJunctions moves every junction to the least-squares intersection of
// its branches: thinning pulls the skeleton junction of lines meeting at a
// shallow angle into the wedge between them.
func refineJunctions(nodes []PixelNode, ls []Polyline) {
	type ray struct{ px, py, dx, dy float64 }
	rays := map[int][]ray{}
	for _, l := range ls {
		for end := 0; end < 2; end++ {
			n := l.StartEnd[end]
			if n < 0 {
				continue
			}
			pts := l.Pts
			if end == 1 {
				pts = reversed(l).Pts
			}
			// sample the branch between 6 and 24 px from the node
			var a, b [2]float64
			acc, ha := 0.0, false
			for i := 1; i < len(pts); i++ {
				acc += math.Hypot(pts[i][0]-pts[i-1][0], pts[i][1]-pts[i-1][1])
				if !ha && acc >= 6 {
					a, ha = pts[i], true
				}
				if acc >= 24 {
					b = pts[i]
					break
				}
				b = pts[i]
			}
			if !ha || math.Hypot(b[0]-a[0], b[1]-a[1]) < 4 {
				continue
			}
			dx, dy := b[0]-a[0], b[1]-a[1]
			l := math.Hypot(dx, dy)
			rays[n] = append(rays[n], ray{a[0], a[1], dx / l, dy / l})
		}
	}
	moved := map[int][2]float64{}
	for n, rs := range rays {
		if len(rs) < 3 {
			continue
		}
		var a11, a12, a22, b1, b2 float64
		for _, r := range rs {
			// (I - d dᵀ)
			m11, m12, m22 := 1-r.dx*r.dx, -r.dx*r.dy, 1-r.dy*r.dy
			a11 += m11
			a12 += m12
			a22 += m22
			b1 += m11*r.px + m12*r.py
			b2 += m12*r.px + m22*r.py
		}
		det := a11*a22 - a12*a12
		if math.Abs(det) < 1e-6 {
			continue
		}
		x, y := (a22*b1-a12*b2)/det, (a11*b2-a12*b1)/det
		if math.Hypot(x-nodes[n].X, y-nodes[n].Y) <= 12 {
			moved[n] = [2]float64{x, y}
		}
	}
	for n, p := range moved {
		nodes[n].X, nodes[n].Y = p[0], p[1]
	}
	for i := range ls {
		if p, ok := moved[ls[i].StartEnd[0]]; ok {
			ls[i].Pts[0] = p
		}
		if p, ok := moved[ls[i].StartEnd[1]]; ok && ls[i].StartEnd[1] >= 0 {
			ls[i].Pts[len(ls[i].Pts)-1] = p
		}
	}
}
