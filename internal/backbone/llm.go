package backbone

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// VisionConfig selects the vision model. OpenAI compatible endpoints
// (TRACED_VISION_API_KEY / _BASE_URL / _MODEL) win over Gemini (GEMINI_API_KEY).
type VisionConfig struct {
	Kind    string // "openai" | "gemini"
	APIKey  string
	BaseURL string
	Model   string
	HTTP    *http.Client
}

// VisionFromEnv returns the configured vision model or nil.
func VisionFromEnv() *VisionConfig {
	if k := os.Getenv("TRACED_VISION_API_KEY"); k != "" {
		return &VisionConfig{Kind: "openai", APIKey: k, BaseURL: orStr(os.Getenv("TRACED_VISION_BASE_URL"), "https://api.openai.com/v1"),
			Model: orStr(os.Getenv("TRACED_VISION_MODEL"), "gpt-4.1-mini")}
	}
	k := os.Getenv("GEMINI_API_KEY")
	if k == "" {
		k = os.Getenv("GOOGLE_API_KEY")
	}
	if k != "" {
		return &VisionConfig{Kind: "gemini", APIKey: k, BaseURL: orStr(os.Getenv("TRACED_GEMINI_BASE_URL"), "https://generativelanguage.googleapis.com/v1beta"),
			Model: orStr(os.Getenv("TRACED_GEMINI_MODEL"), orStr(os.Getenv("TRACED_VISION_MODEL"), "gemini-flash-latest"))}
	}
	return nil
}

// Name is "llm:<model>".
func (v *VisionConfig) Name() string { return "llm:" + v.Model }

const visionPrompt = `You read telecom network maps. The picture shows the terrestrial (land) fibre backbone of an Internet provider%s.
Extract ONLY what is drawn and labelled on the picture:
- "nodes": every city / PoP that is marked (dot, square, label) on the backbone. Use the city name as printed (English spelling if the label is transliterated) and the ISO 3166-1 alpha-2 country code when you can tell it from the map. "x" and "y" are the position of the city's marker as a fraction of the picture width and height (0..1, from the top left corner).
- "links": every drawn line segment of the backbone between two of those nodes ("from"/"to" are node names exactly as in "nodes"). Add "label" only when a capacity / route name is printed on that line.
If two marked cities share a name, keep both and add the state or country in parentheses, e.g. "Springfield (MA)" and "Springfield (IL)", and use those names in "links".
Rules: do not add cities that are not on the picture; do not guess links that are not drawn; skip submarine cables drawn across seas; skip legend entries and logos. If lines pass through a city without a marker, connect the marked cities on both sides.
Answer with strict JSON only, no prose, no markdown:
{"provider":"<name on the map or empty>","nodes":[{"name":"Frankfurt","country":"DE","x":0.512,"y":0.334}],"links":[{"from":"Frankfurt","to":"Amsterdam","label":""}]}`

// VisionNode / VisionLink are the model's answer.
type VisionNode struct {
	Name    string  `json:"name"`
	Country string  `json:"country"`
	X       float64 `json:"x,omitempty"` // marker position, fraction of the width
	Y       float64 `json:"y,omitempty"`
}

// VisionLink is a link read off the picture.
type VisionLink struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"`
}

// VisionAnswer is the strict JSON answer.
type VisionAnswer struct {
	Provider string       `json:"provider"`
	Nodes    []VisionNode `json:"nodes"`
	Links    []VisionLink `json:"links"`
}

// ParseVisionJSON extracts the JSON object from a model reply (tolerating
// code fences and text around it).
func ParseVisionJSON(s string) (*VisionAnswer, error) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1]
		}
	}
	var a VisionAnswer
	if err := json.Unmarshal([]byte(s), &a); err != nil {
		return nil, fmt.Errorf("model answer is not the expected JSON: %w", err)
	}
	if len(a.Nodes) == 0 {
		return nil, errors.New("model found no nodes on the picture")
	}
	return &a, nil
}

// Ask sends the picture (or SVG text) and returns the parsed answer.
func (v *VisionConfig) Ask(ctx context.Context, data []byte, mime, providerHint string) (*VisionAnswer, error) {
	hint := ""
	if providerHint != "" {
		hint = " (" + providerHint + ")"
	}
	prompt := fmt.Sprintf(visionPrompt, hint)
	cl := v.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 4 * time.Minute}
	}
	var body []byte
	var url string
	hdr := http.Header{"Content-Type": {"application/json"}}
	isSVG := mime == "image/svg+xml"
	if isSVG && len(data) > 400<<10 {
		data = data[:400<<10]
	}
	switch v.Kind {
	case "gemini":
		parts := []any{map[string]any{"text": prompt}}
		if isSVG {
			parts = append(parts, map[string]any{"text": "SVG source of the map:\n" + string(data)})
		} else {
			parts = append(parts, map[string]any{"inline_data": map[string]any{"mime_type": mime, "data": base64.StdEncoding.EncodeToString(data)}})
		}
		body, _ = json.Marshal(map[string]any{"contents": []any{map[string]any{"role": "user", "parts": parts}},
			"generationConfig": map[string]any{"temperature": 0, "responseMimeType": "application/json",
				// small city labels need the full picture resolution
				"mediaResolution": orStr(os.Getenv("TRACED_GEMINI_MEDIA_RESOLUTION"), "MEDIA_RESOLUTION_HIGH")}})
		url = strings.TrimRight(v.BaseURL, "/") + "/models/" + v.Model + ":generateContent"
		hdr.Set("x-goog-api-key", v.APIKey)
	default:
		content := []any{map[string]any{"type": "text", "text": prompt}}
		if isSVG {
			content = append(content, map[string]any{"type": "text", "text": "SVG source of the map:\n" + string(data)})
		} else {
			content = append(content, map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data), "detail": "high"}})
		}
		body, _ = json.Marshal(map[string]any{"model": v.Model, "temperature": 0, "response_format": map[string]any{"type": "json_object"},
			"messages": []any{map[string]any{"role": "user", "content": content}}})
		url = strings.TrimRight(v.BaseURL, "/") + "/chat/completions"
		hdr.Set("Authorization", "Bearer "+v.APIKey)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = hdr
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vision API: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		msg := strings.TrimSpace(string(rb))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("vision API: HTTP %d: %s", resp.StatusCode, msg)
	}
	var text string
	if v.Kind == "gemini" {
		var r struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text    string `json:"text"`
						Thought bool   `json:"thought"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if json.Unmarshal(rb, &r) != nil || len(r.Candidates) == 0 {
			return nil, errors.New("vision API: empty Gemini answer")
		}
		for _, p := range r.Candidates[0].Content.Parts {
			if !p.Thought {
				text += p.Text
			}
		}
	} else {
		var r struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if json.Unmarshal(rb, &r) != nil || len(r.Choices) == 0 {
			return nil, errors.New("vision API: empty answer")
		}
		text = r.Choices[0].Message.Content
	}
	if p := os.Getenv("TRACED_VISION_DUMP"); p != "" {
		_ = os.WriteFile(p, []byte(text), 0o644) // raw answer, for debugging / re-import
	}
	return ParseVisionJSON(text)
}

// GraphFromAnswer geocodes the model's nodes and keeps links between
// located nodes. Unresolved names are reported in Notes, never guessed.
//
// Names that are not telecom hubs come from PeeringDB / Nominatim and may be
// a namesake elsewhere ("Garden City" NY vs KS); even a hub alias can hit the
// wrong city ("Kem" vs Kemerovo). When the model gave marker positions, the
// built-in hubs anchor the picture: a local affine fit of their positions
// predicts where every city should be, a clearly nearer namesake replaces a
// far geocode, and a non-hub far off a well-anchored part of the picture is
// dropped.
func GraphFromAnswer(ctx context.Context, a *VisionAnswer, gc *Geocoder) *Graph {
	g := &Graph{}
	var missing, moved, swapped []string
	type placed struct {
		n   VisionNode
		p   *Place
		pos bool
	}
	var ps []placed
	byName := map[string][]int{} // base id → indexes into g.Nodes (namesakes on one picture)
	for _, n := range a.Nodes {
		base := nodeID(n.Name)
		if base == "" {
			continue
		}
		pos := n.X > 0 || n.Y > 0
		dup := false
		for _, i := range byName[base] {
			o := ps[i].n
			if !pos || !ps[i].pos || math.Hypot(o.X-n.X, o.Y-n.Y) < 0.03 {
				dup = true
			}
		}
		if dup {
			continue
		}
		id := base
		if k := len(byName[base]); k > 0 {
			id = fmt.Sprintf("%s-%d", base, k+1)
		}
		p := gc.Lookup(ctx, n.Name, n.Country)
		if p == nil {
			missing = append(missing, n.Name)
			continue
		}
		byName[base] = append(byName[base], len(g.Nodes))
		g.Nodes = append(g.Nodes, Node{ID: id, Name: n.Name, Country: orStr(countryCode(n.Country), p.Country), Lat: p.Lat, Lon: p.Lon, Geo: p.Source})
		ps = append(ps, placed{n, p, pos})
	}
	const farKm = 1500 // marker positions read by a model are rough
	isAnchor := make([]bool, len(ps))
	anchorsExcept := func(skip int) []GCP {
		var out []GCP
		for i, q := range ps {
			if isAnchor[i] && i != skip {
				out = append(out, GCP{X: q.n.X, Y: q.n.Y, Lon: g.Nodes[i].Lon, Lat: g.Nodes[i].Lat})
			}
		}
		return out
	}
	nAnchors := 0
	for i, q := range ps {
		if q.p.Source == "builtin" && q.pos {
			isAnchor[i] = true
			nAnchors++
		}
	}
	// nearer namesake: same name (country first, then anywhere)
	nearer := func(q placed, lat, lon, cur float64) *Place {
		var best *Place
		bd := cur
		ccs := []string{q.n.Country}
		if q.n.Country == "" {
			ccs = []string{"-"}
		}
		for _, cc := range ccs {
			if cc == "-" {
				cc = ""
			}
			for _, c := range gc.Candidates(ctx, cleanName(q.n.Name), cc) {
				if d := haversine(lat, lon, c.Lat, c.Lon); d < bd*0.5 && d < 800 {
					c := c
					best, bd = &c, d
				}
			}
			if best != nil {
				break
			}
		}
		return best
	}
	if nAnchors >= 6 {
		drop := make([]bool, len(ps))
		for i := range ps {
			q, nd := ps[i], &g.Nodes[i]
			if !q.pos {
				continue
			}
			lon, lat, sup, ok := localPredict(anchorsExcept(i), q.n.X, q.n.Y)
			if !ok {
				continue
			}
			d := haversine(lat, lon, nd.Lat, nd.Lon)
			if d <= 300 {
				continue
			}
			// a namesake swap needs a consistent neighbourhood: schematic or
			// distorted parts of a picture predict nonsense
			if sup.resid > 400 {
				continue
			}
			if best := nearer(q, lat, lon, d); best != nil {
				swapped = append(swapped, fmt.Sprintf("%s → %.2f,%.2f", nd.Name, best.Lat, best.Lon))
				nd.Lat, nd.Lon, nd.Geo = best.Lat, best.Lon, best.Source
				if best.Country != "" {
					nd.Country = best.Country
				}
				continue
			}
			if !isAnchor[i] && d > farKm && sup.near < 0.08 && sup.resid < 300 {
				moved = append(moved, fmt.Sprintf("%s (%.0f km off the picture)", nd.Name, d))
				drop[i] = true
			}
		}
		keep := g.Nodes[:0]
		var kps []placed
		for i := range g.Nodes {
			if !drop[i] {
				keep = append(keep, g.Nodes[i])
				kps = append(kps, ps[i])
			}
		}
		g.Nodes, ps = keep, kps
		byName = map[string][]int{}
		for i := range g.Nodes {
			b := nodeID(ps[i].n.Name)
			byName[b] = append(byName[b], i)
		}
	}
	if len(swapped) > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("namesakes matched to their place on the picture (%d): %s", len(swapped), strings.Join(swapped, ", ")))
	}
	if len(moved) > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("geocoded far from their place on the picture, dropped (%d): %s", len(moved), strings.Join(moved, ", ")))
	}
	// a link end naming several namesakes takes the pair closest on the picture
	dropped := 0
	for _, l := range a.Links {
		fa, fb := byName[nodeID(l.From)], byName[nodeID(l.To)]
		bi, bj, bd := -1, -1, math.Inf(1)
		for _, i := range fa {
			for _, j := range fb {
				d := math.Hypot(ps[i].n.X-ps[j].n.X, ps[i].n.Y-ps[j].n.Y)
				if d < bd {
					bi, bj, bd = i, j, d
				}
			}
		}
		if bi < 0 || !g.LinkByNames(g.Nodes[bi].ID, g.Nodes[bj].ID, l.Label) {
			dropped++
		}
	}
	if len(missing) > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("not geocoded (%d): %s", len(missing), strings.Join(missing, ", ")))
	}
	if dropped > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("%d links skipped (unknown or duplicate ends)", dropped))
	}
	return g
}

// support tells how much a prediction can be trusted.
type support struct {
	near  float64 // picture distance (fraction) to the 3rd nearest anchor
	resid float64 // worst km residual of the local fit on its anchors
}

// localPredict estimates lon/lat at picture position x,y from the 6 nearest
// anchors (affine least squares in equirectangular space; good enough to
// catch a namesake in another state or country, not to place a city).
func localPredict(anchors []GCP, x, y float64) (float64, float64, support, bool) {
	type d struct {
		g GCP
		d float64
	}
	ds := make([]d, len(anchors))
	for i, a := range anchors {
		ds[i] = d{a, math.Hypot(a.X-x, a.Y-y)}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].d < ds[j].d })
	var near []GCP
	for _, v := range ds[:min(6, len(ds))] {
		near = append(near, v.g)
	}
	r, err := FromGCPs(near, Equirect)
	if err != nil {
		return 0, 0, support{}, false
	}
	sup := support{near: ds[min(2, len(ds)-1)].d}
	for _, a := range near {
		lo, la := r.LonLat(a.X, a.Y)
		sup.resid = math.Max(sup.resid, haversine(la, lo, a.Lat, a.Lon))
	}
	lon, lat := r.LonLat(x, y)
	return lon, lat, sup, true
}

// LinkList reads a JSON link list in the vision answer format (no GeoJSON
// "type"); nodes may be omitted, link ends are then taken as the nodes.
func LinkList(b []byte) (*VisionAnswer, bool) {
	var probe struct {
		Type  string          `json:"type"`
		Links json.RawMessage `json:"links"`
	}
	if json.Unmarshal(b, &probe) != nil || probe.Type != "" || len(probe.Links) == 0 {
		return nil, false
	}
	var a VisionAnswer
	if json.Unmarshal(b, &a) != nil || len(a.Links) == 0 {
		return nil, false
	}
	have := map[string]bool{}
	for _, n := range a.Nodes {
		have[nodeID(n.Name)] = true
	}
	for _, l := range a.Links {
		for _, e := range []string{l.From, l.To} {
			if k := nodeID(e); k != "" && !have[k] {
				have[k] = true
				a.Nodes = append(a.Nodes, VisionNode{Name: e})
			}
		}
	}
	return &a, true
}
