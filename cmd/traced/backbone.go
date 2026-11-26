package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/backbone"
	"github.com/PalMeany/traced-cli/internal/ui"
)

const backboneUsage = `traced backbone — terrestrial provider backbones from network map pictures

usage:
  traced backbone parse <file|url> --provider NAME [--asn N] [--engine auto|llm|cv|svg]
                        [--region world|europe|russia|us|na|asia|latam] [--bbox minLon,minLat,maxLon,maxLat]
                        [--gcp px,py=lon,lat ...] [--proj mercator|equirect] [--color #hex] [--tolerance N]
                        [--out file.geojson] [--save] [--offline] [--json]
  traced backbone list [--json]                 built-in and saved layers
  traced backbone import <geojson|gml> --provider NAME [--asn N] [--max-link-km N]
                        (GML: Internet Topology Zoo graphs with coordinates; --max-link-km drops submarine hops;
                         JSON link list {"nodes":[{"name","country"}],"links":[{"from","to","label"}]}: names are geocoded)
  traced backbone remove <id>
  traced backbone export [id ...] [--out file]  merged GeoJSON (what the web map shows)

engines (auto: svg for SVG → llm when a key is set → cv):
  llm   vision model reads cities and links; cities are geocoded (built-in hubs, PeeringDB, Nominatim)
        TRACED_VISION_API_KEY + TRACED_VISION_BASE_URL + TRACED_VISION_MODEL (OpenAI compatible) or GEMINI_API_KEY
  cv    local: colour mask → Zhang-Suen skeleton → polyline graph; needs --region/--bbox/--gcp
  svg   local: stroked paths/lines, dots and city labels of an SVG; labels can reference the map by themselves
layers are saved to ~/.cache/traced/backbones/*.geojson and shown on the web map (layer "Terrestrial backbones")
`

type bbFlags struct {
	fs                                        *flag.FlagSet
	provider, engine, region, bbox, proj, col string
	out                                       string
	asn                                       int
	tol, maxKm                                float64
	gcps                                      multiFlag
	save, offline, jsonOut                    bool
}

func newBBFlags() *bbFlags {
	o := &bbFlags{fs: flag.NewFlagSet("backbone", flag.ContinueOnError)}
	f := o.fs
	f.StringVar(&o.provider, "provider", "", "provider name")
	f.IntVar(&o.asn, "asn", 0, "provider ASN")
	f.StringVar(&o.engine, "engine", "auto", "auto|llm|cv|svg")
	f.StringVar(&o.region, "region", "", "map extent preset")
	f.StringVar(&o.bbox, "bbox", "", "map extent minLon,minLat,maxLon,maxLat")
	f.Var(&o.gcps, "gcp", "ground control point px,py=lon,lat (repeat)")
	f.StringVar(&o.proj, "proj", "mercator", "projection mercator|equirect")
	f.StringVar(&o.col, "color", "", "backbone line colour #rrggbb (default: auto)")
	f.Float64Var(&o.tol, "tolerance", 0, "colour tolerance (cv, default 70)")
	f.StringVar(&o.out, "out", "", "write GeoJSON here")
	f.Float64Var(&o.maxKm, "max-link-km", 0, "import gml: drop links longer than this (submarine hops)")
	f.BoolVar(&o.save, "save", false, "save as a map layer")
	f.BoolVar(&o.offline, "offline", false, "no Nominatim lookups")
	f.BoolVar(&o.jsonOut, "json", false, "print JSON")
	f.SetOutput(new(strings.Builder))
	return o
}

func (o *bbFlags) parse(args []string) ([]string, error) {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if j := strings.Index(name, "="); j >= 0 {
				flags = append(flags, "-"+name)
				continue
			}
			fl := o.fs.Lookup(name)
			if fl == nil {
				return nil, fmt.Errorf("unknown flag %s (traced backbone help)", a)
			}
			if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
				flags = append(flags, "-"+name)
				continue
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag %s needs a value", a)
			}
			flags = append(flags, "-"+name, args[i+1])
			i++
			continue
		}
		pos = append(pos, a)
	}
	return pos, o.fs.Parse(flags)
}

func cmdBackbone(args []string) error {
	backbone.Version = app.Version
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(backboneUsage)
		return nil
	}
	sub := args[0]
	o := newBBFlags()
	pos, err := o.parse(args[1:])
	if err != nil {
		return err
	}
	switch sub {
	case "parse":
		return bbParse(o, pos)
	case "list", "ls":
		return bbList(o)
	case "import":
		return bbImport(o, pos)
	case "remove", "rm", "delete":
		if len(pos) != 1 {
			return errors.New("usage: traced backbone remove <id>  (ids: traced backbone list)")
		}
		if err := backbone.Remove(pos[0]); err != nil {
			return err
		}
		fmt.Println("removed", pos[0])
		return nil
	case "export":
		ls := backbone.All(true)
		if len(pos) > 0 {
			var sel []*backbone.FeatureCollection
			for _, l := range ls {
				for _, p := range pos {
					if l.Meta.Slug == p {
						sel = append(sel, l)
					}
				}
			}
			ls = sel
		}
		return writeOut(o.out, backbone.Merge(ls))
	}
	return fmt.Errorf("unknown backbone command %q (traced backbone help)", sub)
}

func writeOut(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func bbParse(o *bbFlags, pos []string) error {
	if len(pos) != 1 {
		return errors.New("usage: traced backbone parse <file|url> --provider NAME [flags]  (traced backbone help)")
	}
	ctx, cancel := signalCtx()
	defer cancel()
	data, err := backbone.Load(ctx, pos[0])
	if err != nil {
		return err
	}
	src := pos[0]
	if !strings.Contains(src, "://") {
		src = filepath.Base(src)
	}
	gc := &backbone.Geocoder{Offline: o.offline}
	opt := backbone.Options{Provider: o.provider, ASN: o.asn, Engine: o.engine, Source: src,
		Ref:    backbone.RefOptions{Region: o.region, BBox: o.bbox, GCPs: o.gcps, Proj: o.proj},
		CV:     backbone.CVOptions{Color: o.col, Tolerance: o.tol},
		SVG:    backbone.SVGOptions{Color: o.col},
		Vision: backbone.VisionFromEnv(), Geocoder: gc}
	if !o.jsonOut {
		eng, _ := backbone.EngineFor(o.engine, backbone.IsSVG(data, src), opt.Vision)
		fmt.Fprintf(os.Stderr, "%s %s (%d KB) engine=%s\n", ui.C("\x1b[1m", "parsing"), src, len(data)>>10, eng)
	}
	g, err := backbone.Parse(ctx, data, opt)
	if err != nil {
		return err
	}
	fc := g.GeoJSON()
	if o.out != "" {
		if err := writeOut(o.out, fc); err != nil {
			return err
		}
	}
	saved := ""
	if o.save {
		if saved, err = backbone.Save(g); err != nil {
			return err
		}
	}
	if o.jsonOut || o.out == "" && !o.save {
		if o.jsonOut || !isTerminal() {
			return writeOut("", fc)
		}
	}
	printGraph(g)
	if o.out != "" {
		fmt.Printf("  geojson → %s\n", o.out)
	}
	if saved != "" {
		fmt.Printf("  saved layer %s → %s (traced map shows it)\n", ui.C("\x1b[36m", fc.Meta.Slug), saved)
	} else if o.out == "" {
		fmt.Println(ui.C("\x1b[90m", "  --save keeps it as a map layer, --out file.geojson writes it, --json prints it"))
	}
	return nil
}

func isTerminal() bool {
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func printGraph(g *backbone.Graph) {
	as := ""
	if g.ASN > 0 {
		as = fmt.Sprintf(" AS%d", g.ASN)
	}
	fmt.Printf("%s%s · %d nodes · %d links · %s\n", ui.C("\x1b[1m", g.Provider), as, len(g.Nodes), len(g.Links), g.ParsedBy)
	names := map[string]string{}
	var ns []string
	for _, n := range g.Nodes {
		names[n.ID] = n.Name
		if n.Name != "" {
			ns = append(ns, n.Name)
		}
	}
	if len(ns) > 0 {
		show := ns
		if len(show) > 30 {
			show = show[:30]
		}
		more := ""
		if len(ns) > 30 {
			more = fmt.Sprintf(" … +%d", len(ns)-30)
		}
		fmt.Printf("  nodes: %s%s\n", strings.Join(show, ", "), more)
	}
	k := 0
	for _, l := range g.Links {
		if names[l.From] != "" && names[l.To] != "" && k < 12 {
			lb := ""
			if l.Label != "" {
				lb = " (" + l.Label + ")"
			}
			fmt.Printf("  %s — %s%s\n", names[l.From], names[l.To], lb)
			k++
		}
	}
	for _, n := range g.Notes {
		ui.Note(os.Stdout, n)
	}
}

func bbList(o *bbFlags) error {
	ls := backbone.All(true)
	ms := backbone.Providers(ls)
	if o.jsonOut {
		return printJSON(ms)
	}
	if len(ms) == 0 {
		fmt.Println("no backbone layers")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROVIDER\tASN\tNODES\tLINKS\tPARSED BY\tSOURCE")
	for _, m := range ms {
		as := "-"
		if m.ASN > 0 {
			as = fmt.Sprintf("AS%d", m.ASN)
		}
		kind := "user"
		if m.Builtin {
			kind = "built-in"
		}
		src := m.Source
		if len(src) > 60 {
			src = src[:57] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", m.Slug, m.Provider, as, m.Nodes, m.Links, orDash(m.ParsedBy)+" ("+kind+")", src)
	}
	tw.Flush()
	fmt.Println(ui.C("\x1b[90m", "user layers: "+backbone.Dir()))
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func bbImport(o *bbFlags, pos []string) error {
	if len(pos) != 1 {
		return errors.New("usage: traced backbone import <file.geojson|file.gml> --provider NAME [--asn N]")
	}
	b, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	var g *backbone.Graph
	if a, ok := backbone.LinkList(b); ok {
		// {"nodes":[{name,country}],"links":[{from,to,label}]}: names are geocoded
		ctx, cancel := signalCtx()
		defer cancel()
		gc := &backbone.Geocoder{Offline: o.offline}
		g = backbone.GraphFromAnswer(ctx, a, gc)
		_ = gc.Save()
		g.Provider, g.ASN, g.ParsedBy = o.provider, o.asn, "import:links"
		if g.Provider == "" {
			g.Provider = a.Provider
		}
		if g.Provider == "" {
			return errors.New("provider name required (--provider)")
		}
		err = g.Validate()
	} else if backbone.IsGML(b) {
		g, err = backbone.FromGML(b, o.provider, o.asn, o.maxKm)
	} else {
		g, err = backbone.FromGeoJSON(b, o.provider, o.asn)
	}
	if err != nil {
		return err
	}
	if g.Source == "" {
		g.Source = filepath.Base(pos[0])
	}
	p, err := backbone.Save(g)
	if err != nil {
		return err
	}
	printGraph(g)
	fmt.Printf("  saved layer %s → %s\n", ui.C("\x1b[36m", backbone.Slug(g.Provider, g.ASN)), p)
	return nil
}
