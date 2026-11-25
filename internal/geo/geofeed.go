package geo

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/whois"
)

// GeofeedEntry is one line of an RFC 8805 geofeed:
// ip_prefix,alpha2code,region,city,postal_code
type GeofeedEntry struct {
	Prefix  *net.IPNet `json:"-"`
	CIDR    string     `json:"prefix"`
	Country string     `json:"country"`
	Region  string     `json:"region,omitempty"`
	City    string     `json:"city,omitempty"`
	Postal  string     `json:"postal,omitempty"`
}

// Geofeed is a parsed feed.
type Geofeed struct {
	URL     string
	Entries []GeofeedEntry
}

// ParseGeofeed parses an RFC 8805 CSV. Comments (#) and malformed lines are skipped.
// Bare addresses are accepted as /32 or /128.
func ParseGeofeed(r io.Reader) ([]GeofeedEntry, error) {
	var out []GeofeedEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ",")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		cidr := f[0]
		if !strings.Contains(cidr, "/") {
			if ip := net.ParseIP(cidr); ip != nil {
				if ip.To4() != nil {
					cidr += "/32"
				} else {
					cidr += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		e := GeofeedEntry{Prefix: n, CIDR: n.String()}
		if len(f) > 1 {
			e.Country = strings.ToUpper(f[1])
		}
		if len(f) > 2 {
			e.Region = f[2]
		}
		if len(f) > 3 {
			e.City = f[3]
		}
		if len(f) > 4 {
			e.Postal = f[4]
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Lookup returns the most specific entry containing ip.
func (g *Geofeed) Lookup(ip net.IP) *GeofeedEntry {
	return LookupGeofeed(g.Entries, ip)
}

// LookupGeofeed does a longest-prefix match over entries.
func LookupGeofeed(entries []GeofeedEntry, ip net.IP) *GeofeedEntry {
	var best *GeofeedEntry
	bestLen := -1
	for i := range entries {
		e := &entries[i]
		if e.Prefix.Contains(ip) {
			l, _ := e.Prefix.Mask.Size()
			if l > bestLen {
				best, bestLen = e, l
			}
		}
	}
	return best
}

// ExtractGeofeedURL finds the RFC 9632 geofeed link in an RDAP/WHOIS document.
func ExtractGeofeedURL(doc string) string { return whois.ExtractGeofeedURL(doc) }

var (
	feedMu    sync.Mutex
	feedCache = map[string]*Geofeed{}
)

// FetchGeofeed downloads (or loads from the disk cache) a geofeed CSV.
func FetchGeofeed(ctx context.Context, url string) (*Geofeed, error) {
	feedMu.Lock()
	if g, ok := feedCache[url]; ok {
		feedMu.Unlock()
		return g, nil
	}
	feedMu.Unlock()
	h := sha1.Sum([]byte(url))
	p := cache.File("geofeed", hex.EncodeToString(h[:])[:20]+".csv")
	if !cache.Fresh(p, 7*24*time.Hour) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", UserAgent)
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("geofeed %s: %s", url, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, err
		}
		_ = os.WriteFile(p, b, 0o644)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := ParseGeofeed(f)
	if err != nil {
		return nil, err
	}
	g := &Geofeed{URL: url, Entries: entries}
	feedMu.Lock()
	feedCache[url] = g
	feedMu.Unlock()
	return g, nil
}

// LoadLocalGeofeeds reads user supplied CSVs (files or directories).
func LoadLocalGeofeeds(paths []string) []*Geofeed {
	var out []*Geofeed
	var files []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.IsDir() {
			m, _ := filepath.Glob(filepath.Join(p, "*.csv"))
			files = append(files, m...)
		} else {
			files = append(files, p)
		}
	}
	for _, fn := range files {
		f, err := os.Open(fn)
		if err != nil {
			continue
		}
		e, _ := ParseGeofeed(f)
		f.Close()
		if len(e) > 0 {
			out = append(out, &Geofeed{URL: "file://" + fn, Entries: e})
		}
	}
	return out
}
