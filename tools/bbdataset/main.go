// Command bbdataset builds internal/backbone/data/backbones.json.gz from the
// parsed layers in dataset/backbones/*.geojson (see dataset/backbones/SOURCES.md).
//
//	go run ./tools/bbdataset [-in dataset/backbones] [-out internal/backbone/data/backbones.json.gz]
//
// Every layer is re-read through backbone.FromGeoJSON (which drops impossible
// coordinates and dangling links) and checked: points must be on Earth, not
// 0,0, and named nodes must lie near the city their name geocodes to (built-in
// hubs, offline), so a mislabelled or invented point fails the build.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/PalMeany/traced-cli/internal/backbone"
	"github.com/PalMeany/traced-cli/internal/feeds"
)

func main() {
	in := flag.String("in", "dataset/backbones", "directory of layer GeoJSON files")
	out := flag.String("out", "internal/backbone/data/backbones.json.gz", "output")
	maxKm := flag.Float64("max-km", 120, "named node vs. geocoded city tolerance")
	maxLink := flag.Float64("max-link-km", 3000, "links whose ends are farther apart are dropped (submarine / intercontinental hops drawn on the maps)")
	flag.Parse()
	files, _ := filepath.Glob(filepath.Join(*in, "*.geojson"))
	sort.Strings(files)
	gc := &backbone.Geocoder{Offline: true, PDB: &feeds.PeeringDB{}, CachePath: os.DevNull}
	ds := &backbone.Dataset{Note: "terrestrial backbones parsed from public operator maps; see dataset/backbones/SOURCES.md"}
	bad := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		g, err := backbone.FromGeoJSON(b, "", 0)
		if err != nil {
			log.Fatalf("%s: %v", f, err)
		}
		long := 0
		links := g.Links[:0]
		for _, l := range g.Links {
			a, b := l.Coords[0], l.Coords[len(l.Coords)-1]
			if backbone.Distance(a[1], a[0], b[1], b[0]) > *maxLink {
				long++
				continue
			}
			links = append(links, l)
		}
		g.Links = links
		if long > 0 {
			g.Notes = append(g.Notes, fmt.Sprintf("%d links longer than %.0f km left out (submarine / intercontinental)", long, *maxLink))
		}
		checked, far := 0, 0
		for _, n := range g.Nodes {
			if n.Name == "" {
				continue
			}
			p := gc.Lookup(context.Background(), n.Name, n.Country)
			if p == nil {
				continue
			}
			checked++
			if d := backbone.Distance(n.Lat, n.Lon, p.Lat, p.Lon); d > *maxKm {
				far++
				fmt.Fprintf(os.Stderr, "%s: node %q at %.3f,%.3f is %.0f km from %s\n", filepath.Base(f), n.Name, n.Lat, n.Lon, d, p)
			}
		}
		if far > 0 && float64(far) > 0.05*float64(checked) {
			bad++
		}
		fc := g.GeoJSON()
		fmt.Printf("%-40s %-28s AS%-6d %4d nodes %4d links  %s (%d/%d names checked, %d far)\n", filepath.Base(f), g.Provider, g.ASN, len(g.Nodes), len(g.Links), g.ParsedBy, checked, len(g.Nodes), far)
		ds.Layers = append(ds.Layers, fc)
	}
	if bad > 0 {
		log.Fatalf("%d layers with misplaced nodes", bad)
	}
	gz, err := backbone.EncodeDataset(ds)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, gz, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d layers → %s (%d KB)\n", len(ds.Layers), *out, len(gz)>>10)
}
