package backbone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/geo"
)

// Place is a geocoded city.
type Place struct {
	Name    string  `json:"name"`
	Country string  `json:"cc,omitempty"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Source  string  `json:"src"` // builtin|peeringdb|nominatim
}

// Geocoder resolves city / PoP names: the built-in telecom hub dictionary
// first, then PeeringDB facility cities, then Nominatim (OpenStreetMap) with
// a local cache in ~/.cache/traced/geocache.json.
type Geocoder struct {
	Offline      bool   // no Nominatim
	NominatimURL string // default https://nominatim.openstreetmap.org
	CachePath    string // default ~/.cache/traced/geocache.json
	HTTP         *http.Client
	PDB          *feeds.PeeringDB // nil = the cached table, if any

	once    sync.Once
	mu      sync.Mutex
	pdbCity map[string]*Place
	cache   map[string][]Place // candidates, best first; empty = known miss
	dirty   bool
	last    time.Time
}

func normKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (g *Geocoder) init() {
	g.once.Do(func() {
		if g.NominatimURL == "" {
			g.NominatimURL = "https://nominatim.openstreetmap.org"
		}
		if g.CachePath == "" {
			g.CachePath = filepath.Join(cache.Dir(), "geocache.json")
		}
		if g.HTTP == nil {
			g.HTTP = &http.Client{Timeout: 15 * time.Second}
		}
		g.cache = map[string][]Place{}
		if b, err := os.ReadFile(g.CachePath); err == nil {
			_ = json.Unmarshal(b, &g.cache)
		}
		pdb := g.PDB
		if pdb == nil {
			pdb = feeds.PDBLocal()
		}
		g.pdbCity = map[string]*Place{}
		if pdb != nil {
			type sum struct {
				lat, lon float64
				n        int
				name, cc string
			}
			acc := map[string]*sum{}
			for _, f := range pdb.Fac {
				if !f.Located() || f.City == "" {
					continue
				}
				for _, k := range []string{normKey(f.City) + "|" + strings.ToLower(f.Country), normKey(f.City)} {
					s := acc[k]
					if s == nil {
						s = &sum{name: f.City, cc: f.Country}
						acc[k] = s
					}
					s.lat += f.Lat
					s.lon += f.Lon
					s.n++
				}
			}
			for k, s := range acc {
				// a bare city name shared by several countries is ambiguous
				g.pdbCity[k] = &Place{Name: s.name, Country: s.cc, Lat: s.lat / float64(s.n), Lon: s.lon / float64(s.n), Source: "peeringdb"}
			}
		}
	})
}

// cleanName strips PoP decorations: "Frankfurt (FRA)", "London-2", "AMS1".
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "(["); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	s = strings.TrimRight(s, "0123456789-_ ")
	return strings.TrimSpace(s)
}

// Lookup geocodes a city / PoP name (cc: optional ISO country code or name).
func (g *Geocoder) Lookup(ctx context.Context, name, cc string) *Place {
	g.init()
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	cc2 := countryCode(cc)
	for _, n := range uniq(name, cleanName(name)) {
		if c := geo.LookupCityIn(n, cc2); c != nil {
			return &Place{Name: c.Name, Country: c.Country, Lat: c.Lat, Lon: c.Lon, Source: "builtin"}
		}
		if cc2 == "" {
			if c := geo.LookupCity(n); c != nil {
				return &Place{Name: c.Name, Country: c.Country, Lat: c.Lat, Lon: c.Lon, Source: "builtin"}
			}
		}
	}
	for _, n := range uniq(name, cleanName(name)) {
		k := normKey(n)
		if cc2 != "" {
			if p := g.pdbCity[k+"|"+strings.ToLower(cc2)]; p != nil {
				return p
			}
		} else if p := g.pdbCity[k]; p != nil {
			return p
		}
	}
	if cc2 == "" && cc == "" {
		if c := geo.LookupCity(cleanName(name)); c != nil {
			return &Place{Name: c.Name, Country: c.Country, Lat: c.Lat, Lon: c.Lon, Source: "builtin"}
		}
	}
	return g.nominatim(ctx, cleanName(name), cc)
}

func uniq(a ...string) []string {
	var out []string
	for _, s := range a {
		if s == "" {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o == s
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

func (g *Geocoder) nominatim(ctx context.Context, name, cc string) *Place {
	if ps := g.Candidates(ctx, name, cc); len(ps) > 0 {
		p := ps[0]
		return &p
	}
	return nil
}

// Candidates returns up to 6 Nominatim matches (best first) for a city name;
// callers that know roughly where the city is pick the nearest one.
func (g *Geocoder) Candidates(ctx context.Context, name, cc string) []Place {
	g.init()
	key := strings.ToLower(name + "|" + cc)
	g.mu.Lock()
	if ps, ok := g.cache[key]; ok {
		g.mu.Unlock()
		out := make([]Place, len(ps))
		for i, p := range ps {
			p.Source = "cache"
			out[i] = p
		}
		return out
	}
	if g.Offline {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()
	c := countryCode(cc)
	var tries []url.Values
	base := func() url.Values {
		return url.Values{"format": {"jsonv2"}, "limit": {"6"}, "addressdetails": {"1"}, "accept-language": {"en"}}
	}
	if c != "" {
		q := base()
		q.Set("city", name)
		q.Set("countrycodes", strings.ToLower(c))
		tries = append(tries, q)
		q = base()
		q.Set("q", name)
		q.Set("countrycodes", strings.ToLower(c))
		tries = append(tries, q)
	} else if cc != "" {
		q := base()
		q.Set("q", name+", "+cc)
		tries = append(tries, q)
	} else {
		q := base()
		q.Set("q", name)
		tries = append(tries, q)
	}
	var out []Place
	for _, q := range tries {
		ps, ok := g.search(ctx, q, name)
		if !ok {
			return nil // network trouble: do not cache a miss
		}
		if out = ps; len(out) > 0 {
			break
		}
	}
	g.mu.Lock()
	g.cache[key] = out
	g.dirty = true
	g.mu.Unlock()
	return out
}

func (g *Geocoder) search(ctx context.Context, q url.Values, name string) ([]Place, bool) {
	// Nominatim usage policy: at most one request per second
	g.mu.Lock()
	if d := time.Second - time.Since(g.last); d > 0 {
		time.Sleep(d)
	}
	g.last = time.Now()
	g.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(g.NominatimURL, "/")+"/search?"+q.Encode(), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "traced/"+Version+" (+https://github.com/PalMeany/traced-cli)")
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, false
	}
	var res []struct {
		Lat, Lon string
		Name     string `json:"name"`
		Address  struct {
			CountryCode string `json:"country_code"`
		} `json:"address"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) != nil {
		return nil, false
	}
	var out []Place
	for _, r := range res {
		lat, e1 := strconv.ParseFloat(r.Lat, 64)
		lon, e2 := strconv.ParseFloat(r.Lon, 64)
		if e1 == nil && e2 == nil {
			out = append(out, Place{Name: orStr(r.Name, name), Country: strings.ToUpper(r.Address.CountryCode), Lat: lat, Lon: lon, Source: "nominatim"})
		}
	}
	return out, true
}

// Save writes the Nominatim cache.
func (g *Geocoder) Save() error {
	g.init()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.dirty {
		return nil
	}
	b, err := json.MarshalIndent(g.cache, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(g.CachePath), 0o755); err != nil {
		return err
	}
	tmp := g.CachePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	g.dirty = false
	return os.Rename(tmp, g.CachePath)
}

// Nearest returns the closest built-in hub within km (for naming CV nodes).
func Nearest(lat, lon, km float64) *geo.City {
	var best *geo.City
	bd := km
	for _, c := range geo.Cities() {
		if d := haversine(lat, lon, c.Lat, c.Lon); d <= bd {
			bd, best = d, c
		}
	}
	return best
}

var countryNames = map[string]string{
	"russia": "RU", "russian federation": "RU", "россия": "RU", "united states": "US", "usa": "US", "united kingdom": "GB", "uk": "GB",
	"great britain": "GB", "england": "GB", "germany": "DE", "france": "FR", "netherlands": "NL", "the netherlands": "NL", "holland": "NL",
	"sweden": "SE", "finland": "FI", "norway": "NO", "denmark": "DK", "poland": "PL", "ukraine": "UA", "kazakhstan": "KZ",
	"latvia": "LV", "lithuania": "LT", "estonia": "EE", "belarus": "BY", "austria": "AT", "switzerland": "CH", "italy": "IT",
	"spain": "ES", "portugal": "PT", "czech republic": "CZ", "czechia": "CZ", "slovakia": "SK", "hungary": "HU", "romania": "RO",
	"bulgaria": "BG", "serbia": "RS", "croatia": "HR", "slovenia": "SI", "greece": "GR", "turkey": "TR", "türkiye": "TR",
	"belgium": "BE", "luxembourg": "LU", "ireland": "IE", "canada": "CA", "mexico": "MX", "brazil": "BR", "argentina": "AR",
	"chile": "CL", "japan": "JP", "china": "CN", "hong kong": "HK", "singapore": "SG", "india": "IN", "australia": "AU",
	"south korea": "KR", "korea": "KR", "taiwan": "TW", "georgia": "GE", "armenia": "AM", "azerbaijan": "AZ", "moldova": "MD",
	"uzbekistan": "UZ", "kyrgyzstan": "KG", "mongolia": "MN", "iran": "IR", "uae": "AE", "united arab emirates": "AE",
	"israel": "IL", "egypt": "EG", "south africa": "ZA", "colombia": "CO", "peru": "PE", "malaysia": "MY", "thailand": "TH",
	"vietnam": "VN", "indonesia": "ID", "philippines": "PH", "new zealand": "NZ",
}

// countryCode normalizes "Germany" / "de" / "DEU"-ish input to ISO alpha-2
// ("" when unknown).
func countryCode(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 2 {
		return strings.ToUpper(s)
	}
	if c, ok := countryNames[strings.ToLower(s)]; ok {
		return c
	}
	return ""
}

func (p *Place) String() string {
	return fmt.Sprintf("%s %.4f,%.4f (%s)", p.Name, p.Lat, p.Lon, p.Source)
}

// Version goes into the Nominatim User-Agent (set by the command).
var Version = "dev"
