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
)

// Candidate is a location claim from one source.
type Candidate struct {
	Source     string  `json:"source"`
	City       string  `json:"city,omitempty"`
	Region     string  `json:"region,omitempty"`
	Country    string  `json:"country,omitempty"`
	Lat        float64 `json:"lat,omitempty"`
	Lon        float64 `json:"lon,omitempty"`
	HasCoords  bool    `json:"has_coords"`
	Confidence float64 `json:"confidence"`
	Detail     string  `json:"detail,omitempty"`
	Rejected   string  `json:"rejected,omitempty"` // physics violation
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
		CityName    string  `json:"cityNameAscii"`
		City        string  `json:"cityName"`
		State       string  `json:"stateName"`
		CountryCode string  `json:"countryCodeAlpha2"`
		Lat         float64 `json:"latitude"`
		Lon         float64 `json:"longitude"`
		Score       float64 `json:"score"`
		IATA        string  `json:"iataCode"`
	} `json:"location"`
}

// IPMap queries the RIPE IPmap "best" engine (free, no key).
func IPMap(ctx context.Context, ip string) (*Candidate, error) {
	var c Candidate
	if cache.Get("ipmap", ip, &c) {
		if c.Source == "" {
			return nil, nil
		}
		return &c, nil
	}
	var r ipmapResp
	if err := getJSON(ctx, "https://ipmap-api.ripe.net/v1/locate/"+ip+"/best", &r); err != nil {
		return nil, err
	}
	if r.Location == nil || r.Location.Lat == 0 && r.Location.Lon == 0 {
		cache.Put("ipmap", ip, Candidate{}, 24*time.Hour)
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
	c = Candidate{Source: SrcIPMap, City: name, Region: l.State, Country: l.CountryCode, Lat: l.Lat, Lon: l.Lon,
		HasCoords: true, Confidence: conf, Detail: fmt.Sprintf("score %.0f", l.Score)}
	cache.Put("ipmap", ip, c, 7*24*time.Hour)
	return &c, nil
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
