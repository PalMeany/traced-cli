package backbone

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// gmlNode is a parsed GML list: key → values (strings or nested lists).
type gmlNode struct {
	keys []string
	vals []any // string | *gmlNode
}

func (n *gmlNode) get(k string) string {
	for i, kk := range n.keys {
		if strings.EqualFold(kk, k) {
			if s, ok := n.vals[i].(string); ok {
				return s
			}
		}
	}
	return ""
}

func (n *gmlNode) lists(k string) []*gmlNode {
	var out []*gmlNode
	for i, kk := range n.keys {
		if strings.EqualFold(kk, k) {
			if l, ok := n.vals[i].(*gmlNode); ok {
				out = append(out, l)
			}
		}
	}
	return out
}

func gmlTokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case unicode.IsSpace(rune(c)):
			i++
		case c == '#': // comment to end of line
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '[' || c == ']':
			out = append(out, string(c))
			i++
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			if j < 0 {
				out = append(out, s[i:])
				return out
			}
			out = append(out, s[i:i+j+2])
			i += j + 2
		default:
			j := i
			for j < len(s) && !unicode.IsSpace(rune(s[j])) && s[j] != '[' && s[j] != ']' {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

func parseGMLList(tok []string, i *int) *gmlNode {
	n := &gmlNode{}
	for *i < len(tok) {
		if tok[*i] == "]" {
			*i++
			return n
		}
		k := tok[*i]
		*i++
		if *i >= len(tok) {
			break
		}
		if tok[*i] == "[" {
			*i++
			n.keys = append(n.keys, k)
			n.vals = append(n.vals, parseGMLList(tok, i))
			continue
		}
		v := tok[*i]
		*i++
		n.keys = append(n.keys, k)
		n.vals = append(n.vals, strings.Trim(v, `"`))
	}
	return n
}

// IsGML sniffs a GML graph file (Internet Topology Zoo format).
func IsGML(b []byte) bool {
	h := string(b)
	if len(h) > 4096 {
		h = h[:4096]
	}
	return strings.Contains(h, "graph [") || strings.Contains(h, "graph\n[")
}

// FromGML reads a GML graph whose nodes carry Latitude/Longitude (Internet
// Topology Zoo). Nodes without coordinates and their edges are skipped and
// counted in Notes; nothing is geocoded or guessed.
// maxLinkKm > 0 drops longer edges (on operator maps those are submarine
// or leased intercontinental hops, not terrestrial backbone).
func FromGML(b []byte, provider string, asn int, maxLinkKm float64) (*Graph, error) {
	tok := gmlTokens(string(b))
	i := 0
	root := parseGMLList(tok, &i)
	gs := root.lists("graph")
	if len(gs) == 0 {
		return nil, errors.New("gml: no graph")
	}
	gr := gs[0]
	g := &Graph{Provider: provider, ASN: asn, ParsedBy: "import:gml"}
	if g.Provider == "" {
		g.Provider = gr.get("Network")
	}
	if g.Provider == "" {
		return nil, errors.New("provider name required (--provider)")
	}
	src := gr.get("Source")
	if d := gr.get("DateObtained"); d != "" {
		g.Notes = append(g.Notes, "map date: "+d)
	} else if d := gr.get("NetworkDate"); d != "" {
		g.Notes = append(g.Notes, "map date: "+d)
	}
	g.Source = src
	ids := map[string]string{}
	skipped := 0
	for _, n := range gr.lists("node") {
		lat, e1 := strconv.ParseFloat(n.get("Latitude"), 64)
		lon, e2 := strconv.ParseFloat(n.get("Longitude"), 64)
		label := n.get("label")
		if e1 != nil || e2 != nil || n.get("Internal") == "0" {
			skipped++
			continue
		}
		if nodeID(label) == "" {
			label = "" // "???" placeholders
		}
		id := nodeID(label)
		if id == "" || g.node(id) != nil {
			id = fmt.Sprintf("%sn%s", id, n.get("id"))
		}
		ids[n.get("id")] = id
		g.Nodes = append(g.Nodes, Node{ID: id, Name: label, Country: countryCode(n.get("Country")), Lat: lat, Lon: lon, Geo: "gml"})
	}
	dropped, long := 0, 0
	for _, e := range gr.lists("edge") {
		a, b := ids[e.get("source")], ids[e.get("target")]
		if a == "" || b == "" {
			dropped++
			continue
		}
		lb := e.get("LinkLabel")
		if lb == "" {
			lb = e.get("label")
		}
		if maxLinkKm > 0 {
			na, nb := g.node(a), g.node(b)
			if haversine(na.Lat, na.Lon, nb.Lat, nb.Lon) > maxLinkKm {
				long++
				continue
			}
		}
		g.LinkByNames(a, b, lb)
	}
	if long > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("%d links longer than %.0f km left out (submarine / intercontinental)", long, maxLinkKm))
	}
	if skipped > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("%d nodes without coordinates skipped", skipped))
	}
	if dropped > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("%d edges to skipped nodes dropped", dropped))
	}
	return g, g.Validate()
}
