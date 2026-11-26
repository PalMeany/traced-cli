package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/whois"
	"github.com/oschwald/maxminddb-golang"
)

// UserAgent for outgoing HTTP requests.
var UserAgent = whois.UserAgent

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Source names.
const (
	SrcRDNS    = "rdns"
	SrcIXP     = "ixp"
	SrcGeofeed = "geofeed"
	SrcIPMap   = "ipmap"
	SrcGeoIP   = "geoip"
	SrcMMDB    = "mmdb"
	SrcInterp  = "interp"
	SrcRIR     = "registry"
)

// SourcePriority returns the explicit trust rank of a geolocation source
// (1 = highest priority, 8 = lowest).
func SourcePriority(src string) int {
	switch src {
	case SrcIXP:
		return 1
	case SrcGeofeed:
		return 2
	case SrcRDNS:
		return 3
	case SrcIPMap:
		return 4
	case SrcMMDB:
		return 5
	case SrcGeoIP:
		return 6
	case SrcRIR:
		return 7
	case SrcInterp:
		return 8
	default:
		return 9
	}
}

// Area is a physical constraint: the address is within RadiusKm of a point
// (RIPE IPmap's latency engine: a RIPE Atlas probe saw it at a low RTT).
type Area struct {
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	RadiusKm float64 `json:"radius_km"`
	From     string  `json:"from,omitempty"`
}

// Contains reports whether (lat, lon) lies inside the area (with SlackKm).
func (a *Area) Contains(lat, lon float64) bool {
	return a == nil || DistanceKm(a.Lat, a.Lon, lat, lon) <= a.RadiusKm+SlackKm
}

// GuessRadiusKm: an IPmap answer backed only by the latency radius plus the
// "worlds" engine is just the most populous city inside that circle. When the
// circle is this wide it spans several countries, so the city/country is a
// guess, not a measurement.
const GuessRadiusKm = 250.0

// GuessConfidence keeps such a pick just above a plain GeoIP answer (it is at
// least bounded by a measurement) but below anything that can anchor others.
const GuessConfidence = 0.42

// Candidate is a location claim from one source.
type Candidate struct {
	Source     string  `json:"source"`
	Priority   int     `json:"priority,omitempty"` // explicit source priority (1 = highest)
	Chosen     bool    `json:"chosen,omitempty"`   // selected as the primary verdict
	City       string  `json:"city,omitempty"`
	Region     string  `json:"region,omitempty"`
	Country    string  `json:"country,omitempty"`
	Lat        float64 `json:"lat,omitempty"`
	Lon        float64 `json:"lon,omitempty"`
	HasCoords  bool    `json:"has_coords"`
	Confidence float64 `json:"confidence"`
	Detail     string  `json:"detail,omitempty"`
	Rejected   string  `json:"rejected,omitempty"` // physics violation
	Guess      bool    `json:"guess,omitempty"`    // population pick, not a measurement
	Area       *Area   `json:"area,omitempty"`     // where the address must be (latency)
}

func getJSON(ctx context.Context, url string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// ---------- RIPE IPmap ----------

type ipmapResp struct {
	Location *struct {
		CityName      string                     `json:"cityNameAscii"`
		City          string                     `json:"cityName"`
		State         string                     `json:"stateName"`
		CountryCode   string                     `json:"countryCodeAlpha2"`
		Lat           float64                    `json:"latitude"`
		Lon           float64                    `json:"longitude"`
		Score         float64                    `json:"score"`
		IATA          string                     `json:"iataCode"`
		Contributions map[string]json.RawMessage `json:"contributions"`
	} `json:"location"`
}

type ipmapLatency struct {
	Score  float64 `json:"score"`
	Source string  `json:"sourceId"`
	MinRTT float64 `json:"minRtt"`
	Radius *struct {
		Lat  float64 `json:"latitude"`
		Lon  float64 `json:"longitude"`
		MaxM float64 `json:"maxDistanceMetres"`
	} `json:"radius"`
}

// ParseIPMap turns an IPmap /best answer into a candidate (nil when empty).
func ParseIPMap(b []byte) (*Candidate, error) {
	var r ipmapResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Location == nil || r.Location.Lat == 0 && r.Location.Lon == 0 {
		return nil, nil
	}
	l := r.Location
	conf := 0.5
	switch {
	case l.Score >= 40:
		conf = 0.85
	case l.Score >= 15:
		conf = 0.7
	}
	name := l.CityName
	if name == "" {
		name = l.City
	}
	c := Candidate{Source: SrcIPMap, City: name, Region: l.State, Country: l.CountryCode, Lat: l.Lat, Lon: l.Lon,
		HasCoords: true, Confidence: conf, Detail: fmt.Sprintf("score %.0f", l.Score)}
	measured := false // an engine that actually points at a place (rdns, ixp, crowdsourced, anycast...)
	for k, raw := range l.Contributions {
		switch k {
		case "worlds":
		case "latency":
			var lat ipmapLatency
			if json.Unmarshal(raw, &lat) == nil && lat.Radius != nil && lat.Radius.MaxM > 0 {
				c.Area = &Area{Lat: lat.Radius.Lat, Lon: lat.Radius.Lon, RadiusKm: lat.Radius.MaxM / 1000,
					From: strings.TrimPrefix(lat.Source, "https://atlas.ripe.net/")}
			}
		default:
			measured = true
		}
	}
	if !measured && c.Area != nil && c.Area.RadiusKm > GuessRadiusKm {
		c.Guess = true
		c.Confidence = minF([]float64{c.Confidence, GuessConfidence})
		c.Detail += fmt.Sprintf(", population pick inside a %.0f km latency radius", c.Area.RadiusKm)
	}
	return &c, nil
}

// IPMap queries the RIPE IPmap "best" engine (free, no key).
func IPMap(ctx context.Context, ip string) (*Candidate, error) {
	var c Candidate
	if cache.Get("ipmap-v2", ip, &c) {
		if c.Source == "" {
			return nil, nil
		}
		return &c, nil
	}
	var raw json.RawMessage
	if err := getJSON(ctx, "https://ipmap-api.ripe.net/v1/locate/"+ip+"/best", &raw); err != nil {
		return nil, err
	}
	p, err := ParseIPMap(raw)
	if err != nil {
		return nil, err
	}
	if p == nil {
		cache.Put("ipmap-v2", ip, Candidate{}, 24*time.Hour)
		return nil, nil
	}
	cache.Put("ipmap-v2", ip, *p, 7*24*time.Hour)
	return p, nil
}

// ---------- ip-api (batch) ----------

type ipapiRec struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

// GeoIPBatch resolves many IPs through ip-api.com (or ipinfo.io when a token is set).
func GeoIPBatch(ctx context.Context, ips []string, ipinfoToken string) map[string]*Candidate {
	out := map[string]*Candidate{}
	var todo []string
	for _, ip := range ips {
		var c Candidate
		if cache.Get("geoip", ip, &c) {
			if c.Source != "" {
				out[ip] = &c
			}
			continue
		}
		todo = append(todo, ip)
	}
	if len(todo) == 0 {
		return out
	}
	if ipinfoToken != "" {
		for _, ip := range todo {
			var r struct {
				City, Region, Country, Loc, Org string
			}
			if err := getJSON(ctx, "https://ipinfo.io/"+ip+"/json?token="+ipinfoToken, &r); err != nil {
				continue
			}
			c := Candidate{Source: SrcGeoIP, City: r.City, Region: r.Region, Country: r.Country, Confidence: 0.45, Detail: "ipinfo.io"}
			if p := strings.Split(r.Loc, ","); len(p) == 2 {
				c.Lat, _ = strconv.ParseFloat(p[0], 64)
				c.Lon, _ = strconv.ParseFloat(p[1], 64)
				c.HasCoords = true
			}
			out[ip] = &c
			cache.Put("geoip", ip, c, 7*24*time.Hour)
		}
		return out
	}
	if len(todo) <= 3 {
		// the batch endpoint is limited to 15 req/min, the single one to 45 req/min
		for _, ip := range todo {
			var r ipapiRec
			if err := getJSON(ctx, "http://ip-api.com/json/"+ip+"?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,query", &r); err != nil {
				continue
			}
			if r.Status != "success" {
				cache.Put("geoip", ip, Candidate{}, 24*time.Hour)
				continue
			}
			c := Candidate{Source: SrcGeoIP, City: r.City, Region: r.Region, Country: r.CountryCode,
				Lat: r.Lat, Lon: r.Lon, HasCoords: true, Confidence: 0.4, Detail: "ip-api.com " + r.ISP}
			out[ip] = &c
			cache.Put("geoip", ip, c, 7*24*time.Hour)
		}
		return out
	}
	for i := 0; i < len(todo); i += 100 {
		end := i + 100
		if end > len(todo) {
			end = len(todo)
		}
		body, _ := json.Marshal(todo[i:end])
		req, _ := http.NewRequestWithContext(ctx, "POST",
			"http://ip-api.com/batch?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,query", bytes.NewReader(body))
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		var recs []ipapiRec
		_ = json.NewDecoder(resp.Body).Decode(&recs)
		resp.Body.Close()
		for _, r := range recs {
			if r.Status != "success" {
				cache.Put("geoip", r.Query, Candidate{}, 24*time.Hour)
				continue
			}
			c := Candidate{Source: SrcGeoIP, City: r.City, Region: r.Region, Country: r.CountryCode,
				Lat: r.Lat, Lon: r.Lon, HasCoords: true, Confidence: 0.4, Detail: "ip-api.com " + r.ISP}
			out[r.Query] = &c
			cache.Put("geoip", r.Query, c, 7*24*time.Hour)
		}
	}
	return out
}

// ---------- local MaxMind / DB-IP mmdb ----------

// MMDB wraps a GeoLite2-City / dbip-city compatible database.
type MMDB struct{ r *maxminddb.Reader }

// OpenMMDB opens a .mmdb file.
func OpenMMDB(path string) (*MMDB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &MMDB{r: r}, nil
}

// Lookup returns a candidate for ip.
func (m *MMDB) Lookup(ip net.IP) *Candidate {
	if m == nil {
		return nil
	}
	var rec struct {
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Sub []struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
		Loc struct {
			Lat float64 `maxminddb:"latitude"`
			Lon float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	if err := m.r.Lookup(ip, &rec); err != nil || rec.Country.ISO == "" {
		return nil
	}
	c := &Candidate{Source: SrcMMDB, City: rec.City.Names["en"], Country: rec.Country.ISO,
		Lat: rec.Loc.Lat, Lon: rec.Loc.Lon, HasCoords: rec.Loc.Lat != 0 || rec.Loc.Lon != 0, Confidence: 0.45, Detail: "local mmdb"}
	if len(rec.Sub) > 0 {
		c.Region = rec.Sub[0].Names["en"]
	}
	return c
}

// Close the database.
func (m *MMDB) Close() {
	if m != nil {
		m.r.Close()
	}
}

// IPInfoLite queries ipinfo.io for an independent GeoIP candidate (works with
// or without a token; cached 7 days; fails silently on rate limits).
func IPInfoLite(ctx context.Context, ip, token string) *Candidate {
	var c Candidate
	if cache.Get("ipinfo", ip, &c) {
		if c.Source == "" {
			return nil
		}
		return &c
	}
	u := "https://ipinfo.io/" + ip + "/json"
	if token != "" {
		u += "?token=" + token
	}
	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var r struct {
		City, Region, Country, Loc, Org string
		Bogon                           bool
	}
	if err := getJSON(tctx, u, &r); err != nil {
		return nil
	}
	if r.Bogon || (r.Country == "" && r.City == "") {
		cache.Put("ipinfo", ip, Candidate{}, 24*time.Hour)
		return nil
	}
	c = Candidate{Source: SrcGeoIP, Priority: SourcePriority(SrcGeoIP), City: r.City, Region: r.Region, Country: r.Country, Confidence: 0.44, Detail: "ipinfo.io"}
	if p := strings.Split(r.Loc, ","); len(p) == 2 {
		lat, e1 := strconv.ParseFloat(strings.TrimSpace(p[0]), 64)
		lon, e2 := strconv.ParseFloat(strings.TrimSpace(p[1]), 64)
		if e1 == nil && e2 == nil && (lat != 0 || lon != 0) {
			c.Lat, c.Lon, c.HasCoords = lat, lon, true
		}
	}
	cache.Put("ipinfo", ip, c, 7*24*time.Hour)
	return &c
}

// ---------- PTR ----------

// PTR does a reverse lookup with a short timeout (cached).
func PTR(ctx context.Context, ip string) string {
	var h string
	if cache.Get("ptr", ip, &h) {
		return h
	}
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		h = strings.TrimSuffix(names[0], ".")
	}
	var de *net.DNSError
	if err == nil || h != "" || errors.As(err, &de) && de.IsNotFound {
		cache.Put("ptr", ip, h, 3*24*time.Hour)
	}
	return h
}
