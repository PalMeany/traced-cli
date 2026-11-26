# Built-in terrestrial backbone dataset

Built by `go run ./tools/bbdataset` into `internal/backbone/data/backbones.json.gz`.
Each layer here is the output of `traced backbone` run on a public operator map; positions
come from geocoding the city names printed on the map (built-in telecom hub dictionary →
PeeringDB → OpenStreetMap Nominatim), from the operator's own GeoJSON, or from the Topology
Zoo graph — never from guessing. Names that could not be geocoded were left out (listed in the
layer `notes`). Links whose ends are more than 3000 km apart (submarine / intercontinental hops
drawn on the maps) are left out.

Routes on marketing maps are often schematic: a link means "these cities are connected on the
provider's map", not the exact fibre path.

| layer | provider | source | engine | date |
|---|---|---|---|---|
| `hurricane-electric-as6939` | Hurricane Electric AS6939 | https://he.net — HurricaneElectricNetworkMap.pdf, page 1 rendered to PNG; 141 of 163 nodes are confirmed by the PoP address list on page 2 (the rest are the map's orange "coming soon" markers and region labels) | `llm` (Gemini) + geocoding | 2026 |
| `cogent-as174` | Cogent AS174 | cogentco.com network maps: Europe, Americas, Asia-Pacific (PDF, page 1 rendered) | `llm` (Gemini) + geocoding | Q4 2026 |
| `zayo-as6461` | Zayo AS6461 | Zayo Mapbook, IP network slide | `llm` (Gemini) + geocoding | Q4 2026 |
| `ntt-as2914` | NTT AS2914 | NTT Global IP Network map (schematic "globe" insets: city level only) | `llm` (Gemini) + geocoding | 2024 |
| `arelion-as1299` | Arelion AS1299 | arelion.com interactive network map: backbone routes (vector tiles, zoom 4) and PoP locations (GeoJSON); segments tagged with submarine cable names left out | `import` (GeoJSON) | 2026 |
| `gtt-as3257` | GTT AS3257 | Internet Topology Zoo `Tinet.gml` (Tinet, now GTT), CC BY — mirror github.com/mroughan/InternetTopologyZoo | `import` (GML, `--max-link-km 2500`) | 2010 |
| `rostelecom-as12389` | Rostelecom AS12389 | ComNews «Backbone Networks in Russia / Магистральные сети связи в России», Nov–Dec 2025, operator layer rendered alone | `llm` (Gemini) + geocoding | 2025 |
| `transtelecom-ttk-as20485` | TransTeleCom (ТТК) AS20485 | same poster, TransTeleCom layer | `llm` + geocoding | 2025 |
| `megafon-as31133` | MegaFon AS31133 | same poster, MegaFon layer | `llm` + geocoding | 2025 |
| `mts-as8359` | MTS AS8359 | same poster, MTS layer | `llm` + geocoding | 2025 |
| `vimpelcom-beeline-as3216` | VimpelCom (Beeline) AS3216 | same poster, VimpelCom layer | `llm` + geocoding | 2025 |
| `retn-as9002` | RETN AS9002 | same poster, RetnNet layer (Russia/CIS part of RETN only) | `llm` + geocoding | 2025 |

© the operators for their maps; the ComNews poster data © ComNews Group (attribution required);
Topology Zoo data CC BY. The layers are a derived, simplified index (city pairs), meant for
orientation and trace hints.

Re-create a layer, e.g.:

    GEMINI_API_KEY=… traced backbone parse HurricaneElectricNetworkMap.png --provider "Hurricane Electric" --asn 6939 --engine llm --out dataset/backbones/hurricane-electric-as6939.geojson
    traced backbone import Tinet.gml --provider GTT --asn 3257 --max-link-km 2500
    go run ./tools/bbdataset
