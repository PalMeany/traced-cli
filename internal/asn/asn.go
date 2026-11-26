// Package asn builds a provider profile of an autonomous system from public
// sources queried in parallel: PeeringDB (network type, traffic, peering
// policy, exchanges and facilities), CAIDA AS Rank (global rank, customer
// cone, degree), RIPEstat (announced prefixes, neighbours, visibility) and
// APNIC Labs (eyeball population, from the local feed cache). Every source
// has its own timeout and cache; a source that fails, times out or answers
// 429 is reported as such and the rest of the profile still renders.
package asn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/whois"
)

// UserAgent of all requests.
var UserAgent = "traced-cli/1.2 (+https://github.com/PalMeany/traced-cli)"

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Endpoints (overridable in tests).
var (
	PeeringDBURL = "https://www.peeringdb.com/api"
	CAIDAURL     = "https://api.asrank.caida.org/v2/graphql"
	RIPEstatURL  = "https://stat.ripe.net/data"
)

// IX is an exchange the network is connected to.
type IX struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	City     string  `json:"city,omitempty"`
	Country  string  `json:"cc,omitempty"`
	SpeedMb  int     `json:"speed_mbps,omitempty"` // sum of all ports
	Ports    int     `json:"ports,omitempty"`
	IPv4     string  `json:"ipv4,omitempty"`
	IPv6     string  `json:"ipv6,omitempty"`
	RSPeer   bool    `json:"rs_peer,omitempty"`
	Lat      float64 `json:"lat,omitempty"`
	Lon      float64 `json:"lon,omitempty"`
	Operates bool    `json:"operational,omitempty"`
}

// Facility is a data centre the network is present in.
type Facility struct {
	ID      int     `json:"id"`
	Name    string  `json:"name"`
	City    string  `json:"city,omitempty"`
	Country string  `json:"cc,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

// PeeringDB is the self-declared network record.
type PeeringDB struct {
	ID              int        `json:"id"`
	Name            string     `json:"name"`
	AKA             string     `json:"aka,omitempty"`
	Website         string     `json:"website,omitempty"`
	Type            string     `json:"type,omitempty"`    // info_type: NSP, Content, Cable/DSL/ISP…
	Traffic         string     `json:"traffic,omitempty"` // info_traffic: "1-5Tbps"
	Ratio           string     `json:"ratio,omitempty"`   // info_ratio
	Scope           string     `json:"scope,omitempty"`
	Prefixes4       int        `json:"prefixes4,omitempty"` // declared max prefixes
	Prefixes6       int        `json:"prefixes6,omitempty"`
	Policy          string     `json:"policy,omitempty"` // policy_general: Open/Selective/Restrictive/No
	PolicyURL       string     `json:"policy_url,omitempty"`
	PolicyLocations string     `json:"policy_locations,omitempty"`
	PolicyContracts string     `json:"policy_contracts,omitempty"`
	IRRASSet        string     `json:"irr_as_set,omitempty"`
	IXCount         int        `json:"ix_count"`
	FacCount        int        `json:"fac_count"`
	IXs             []IX       `json:"ixs,omitempty"`
	Facilities      []Facility `json:"facilities,omitempty"`
	Updated         string     `json:"updated,omitempty"`
}

// Rank is the CAIDA AS Rank view.
type Rank struct {
	Rank          int     `json:"rank"`
	Name          string  `json:"name,omitempty"`
	Org           string  `json:"org,omitempty"`
	Country       string  `json:"country,omitempty"`
	CountryName   string  `json:"country_name,omitempty"`
	Clique        bool    `json:"clique,omitempty"` // tier-1 clique member
	ConeASNs      int     `json:"cone_asns"`
	ConePrefixes  int     `json:"cone_prefixes"`
	ConeAddresses int64   `json:"cone_addresses"`
	Providers     int     `json:"providers"`
	Peers         int     `json:"peers"`
	Customers     int     `json:"customers"`
	Siblings      int     `json:"siblings,omitempty"`
	Degree        int     `json:"degree"`
	Lat           float64 `json:"lat,omitempty"`
	Lon           float64 `json:"lon,omitempty"`
}

// Neighbour is an adjacent AS seen in BGP.
type Neighbour struct {
	ASN   int    `json:"asn"`
	Type  string `json:"type"` // left (towards the core: upstream/peer) | right (downstream) | uncertain
	Power int    `json:"power"`
}

// Routing is the RIPEstat BGP view.
type Routing struct {
	Holder       string      `json:"holder,omitempty"`
	V4           []string    `json:"v4,omitempty"`
	V6           []string    `json:"v6,omitempty"`
	CountV4      int         `json:"count_v4"`
	CountV6      int         `json:"count_v6"`
	AddressesV4  int64       `json:"addresses_v4,omitempty"` // announced IPv4 space (overlaps merged)
	Slash48sV6   int64       `json:"slash48s_v6,omitempty"`
	Left         int         `json:"neighbours_left,omitempty"`
	Right        int         `json:"neighbours_right,omitempty"`
	Uncertain    int         `json:"neighbours_uncertain,omitempty"`
	Upstreams    []Neighbour `json:"upstreams,omitempty"` // strongest "left" neighbours
	VisV4Seeing  int         `json:"vis_v4_seeing,omitempty"`
	VisV4Total   int         `json:"vis_v4_total,omitempty"`
	VisV6Seeing  int         `json:"vis_v6_seeing,omitempty"`
	VisV6Total   int         `json:"vis_v6_total,omitempty"`
	FirstSeen    string      `json:"first_seen,omitempty"`
	PrefixesFrom string      `json:"prefixes_window,omitempty"`
}

// Eyeballs summarises APNIC Labs user estimates.
type Eyeballs struct {
	Users    int64            `json:"users"`
	PctWorld float64          `json:"pct_world"`
	Top      []feeds.Eyeballs `json:"by_country,omitempty"`
	Date     string           `json:"date,omitempty"`
}

// Source is the outcome of one data source.
type Source struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Cached  bool   `json:"cached,omitempty"`
	Skipped string `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
	TookMs  int64  `json:"took_ms,omitempty"`
}

// Report is the full profile.
type Report struct {
	Query     string     `json:"query"`
	IP        string     `json:"ip,omitempty"` // when resolved from an IP / domain
	ASN       int        `json:"asn"`
	Name      string     `json:"name,omitempty"`
	Prefix    string     `json:"prefix,omitempty"` // origin prefix of IP
	Country   string     `json:"country,omitempty"`
	PeeringDB *PeeringDB `json:"peeringdb,omitempty"`
	Rank      *Rank      `json:"rank,omitempty"`
	Routing   *Routing   `json:"routing,omitempty"`
	Eyeballs  *Eyeballs  `json:"eyeballs,omitempty"`
	Sources   []Source   `json:"sources"`
	Notes     []string   `json:"notes,omitempty"`
}

// Options select the parts to fetch.
type Options struct {
	Neighbours bool          // RIPEstat asn-neighbours
	Visibility bool          // RIPEstat routing-status
	Prefixes   bool          // keep the full prefix lists in the report
	Timeout    time.Duration // per source (default 15s)
	NoNetwork  bool          // cache and local feeds only
}

// Full is what `traced asn` asks for.
var Full = Options{Neighbours: true, Visibility: true, Prefixes: true}

// ParseASN accepts "AS13335", "as13335", "13335", "ASN13335".
func ParseASN(s string) (int, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "ASN"), "AS")
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > math.MaxUint32 {
		return 0, false
	}
	return n, true
}

// Target is a query resolved to an AS.
type Target struct {
	ASN     int
	IP      string
	Prefix  string
	Name    string
	Country string
}

// Resolve turns "AS13335", an IP or a domain into an ASN.
func Resolve(ctx context.Context, q string) (*Target, error) {
	q = strings.TrimSpace(q)
	if n, ok := ParseASN(q); ok {
		return &Target{ASN: n}, nil
	}
	ip := net.ParseIP(q)
	if ip == nil {
		if !strings.Contains(q, ".") {
			return nil, fmt.Errorf("%q is not an ASN, IP or domain", q)
		}
		c, cancel := context.WithTimeout(ctx, 8*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(c, q)
		cancel()
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %s: %v", q, err)
		}
		ip = addrs[0].IP
		for _, a := range addrs {
			if a.IP.To4() != nil {
				ip = a.IP
				break
			}
		}
	}
	a, err := whois.LookupASN(ctx, ip)
	if err != nil || a == nil {
		if err == nil {
			err = errors.New("not announced in BGP")
		}
		return &Target{IP: ip.String()}, fmt.Errorf("origin AS of %s: %v", ip, err)
	}
	return &Target{ASN: a.ASN, IP: ip.String(), Prefix: a.Prefix, Name: a.Name, Country: a.Country}, nil
}

// Lookup resolves q and builds the report.
func Lookup(ctx context.Context, q string, o Options) (*Report, error) {
	t, err := Resolve(ctx, q)
	if err != nil {
		return nil, err
	}
	r := Profile(ctx, t.ASN, o)
	r.Query, r.IP, r.Prefix = q, t.IP, t.Prefix
	if r.Name == "" {
		r.Name = t.Name
	}
	if r.Country == "" {
		r.Country = t.Country
	}
	return r, nil
}

// Profile queries every source for asn in parallel.
func Profile(ctx context.Context, asn int, o Options) *Report {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	r := &Report{Query: "AS" + strconv.Itoa(asn), ASN: asn}
	type job struct {
		name string
		fn   func(ctx context.Context) (bool, error) // cached?, err
	}
	var mu sync.Mutex
	jobs := []job{
		{"peeringdb", func(ctx context.Context) (bool, error) {
			p, c, err := PeeringDBNet(ctx, asn, o.NoNetwork)
			mu.Lock()
			r.PeeringDB = p
			mu.Unlock()
			return c, err
		}},
		{"caida", func(ctx context.Context) (bool, error) {
			k, c, err := CAIDARank(ctx, asn, o.NoNetwork)
			mu.Lock()
			r.Rank = k
			mu.Unlock()
			return c, err
		}},
		{"ripestat", func(ctx context.Context) (bool, error) {
			rt, c, err := RIPE(ctx, asn, o)
			mu.Lock()
			r.Routing = rt
			mu.Unlock()
			return c, err
		}},
		{"apnic", func(ctx context.Context) (bool, error) {
			e, date, note := feeds.EyeballsOf(ctx, asn)
			mu.Lock()
			defer mu.Unlock()
			if note != "" {
				r.Notes = append(r.Notes, note)
			}
			if len(e) == 0 {
				if date == "" {
					return true, errors.New(orStr(note, "aspop feed unavailable"))
				}
				return true, errSkip("no eyeball estimate (not an access network, or too few samples)")
			}
			ey := &Eyeballs{Date: date}
			for _, x := range e {
				ey.Users += x.Users
				ey.PctWorld += x.PctWorld
			}
			ey.Top = e
			if len(ey.Top) > 8 {
				ey.Top = ey.Top[:8]
			}
			r.Eyeballs = ey
			return true, nil
		}},
	}
	r.Sources = make([]Source, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			t0 := time.Now()
			cached, err := j.fn(c)
			s := Source{Name: j.name, OK: err == nil, Cached: cached, TookMs: time.Since(t0).Milliseconds()}
			var sk errSkip
			var pe partialErr
			switch {
			case err == nil:
			case errors.As(err, &sk):
				s.OK, s.Skipped = true, string(sk)
			case errors.As(err, &pe):
				s.OK, s.Error = true, string(pe)
			default:
				s.Error = describe(err, c)
			}
			r.Sources[i] = s
		}(i, j)
	}
	wg.Wait()
	switch {
	case r.PeeringDB != nil && r.PeeringDB.Name != "":
		r.Name = r.PeeringDB.Name
	case r.Rank != nil && r.Rank.Name != "":
		r.Name = r.Rank.Name
	case r.Routing != nil && r.Routing.Holder != "":
		r.Name = r.Routing.Holder
	}
	if r.Rank != nil {
		r.Country = r.Rank.Country
	}
	return r
}

type errSkip string

func (e errSkip) Error() string { return string(e) }

// describe turns transport errors into short human text.
func describe(err error, ctx context.Context) string {
	var he *httpError
	switch {
	case errors.As(err, &he) && he.Code == 429:
		if he.RetryAfter > time.Minute {
			return fmt.Sprintf("rate limited (HTTP 429), retry in %d min", int(he.RetryAfter.Minutes()+0.5))
		}
		return "rate limited (HTTP 429), try later"
	case errors.As(err, &he):
		return fmt.Sprintf("HTTP %d", he.Code)
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded:
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

type httpError struct {
	Code       int
	URL        string
	RetryAfter time.Duration
}

func (e *httpError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.URL, e.Code) }

func do(ctx context.Context, method, url string, body []byte, hdr map[string]string, v any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	for k, x := range hdr {
		req.Header.Set(k, x)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// one polite retry when the server asks for a short pause
	if resp.StatusCode == 429 && !retried(ctx) {
		if wait, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			t := time.NewTimer(wait)
			select {
			case <-t.C:
				return do(context.WithValue(ctx, retryKey{}, true), method, url, body, hdr, v)
			case <-ctx.Done():
				t.Stop()
				return &httpError{Code: 429, URL: url}
			}
		}
	}
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		he := &httpError{Code: resp.StatusCode, URL: url}
		if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 {
			he.RetryAfter = time.Duration(n) * time.Second
		}
		return he
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

type retryKey struct{}

func retried(ctx context.Context) bool { return ctx.Value(retryKey{}) != nil }

// retryAfter accepts a delay in seconds up to 6 s (longer waits are not worth it).
func retryAfter(h string) (time.Duration, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || n < 0 || n > 6 {
		return 0, false
	}
	return time.Duration(n)*time.Second + 200*time.Millisecond, true
}

// ---------------- PeeringDB ----------------

type pdbNet struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	AKA             string `json:"aka"`
	Website         string `json:"website"`
	ASN             int    `json:"asn"`
	IRRASSet        string `json:"irr_as_set"`
	InfoType        string `json:"info_type"`
	InfoTraffic     string `json:"info_traffic"`
	InfoRatio       string `json:"info_ratio"`
	InfoScope       string `json:"info_scope"`
	InfoPrefixes4   int    `json:"info_prefixes4"`
	InfoPrefixes6   int    `json:"info_prefixes6"`
	PolicyGeneral   string `json:"policy_general"`
	PolicyURL       string `json:"policy_url"`
	PolicyLocations string `json:"policy_locations"`
	PolicyContracts string `json:"policy_contracts"`
	IXCount         int    `json:"ix_count"`
	FacCount        int    `json:"fac_count"`
	Updated         string `json:"updated"`
	NetFac          []struct {
		FacID   int    `json:"fac_id"`
		Name    string `json:"name"`
		City    string `json:"city"`
		Country string `json:"country"`
	} `json:"netfac_set"`
	NetIXLan []struct {
		IXID        int    `json:"ix_id"`
		Name        string `json:"name"`
		Speed       int    `json:"speed"`
		IPAddr4     string `json:"ipaddr4"`
		IPAddr6     string `json:"ipaddr6"`
		IsRSPeer    bool   `json:"is_rs_peer"`
		Operational bool   `json:"operational"`
	} `json:"netixlan_set"`
}

// ParsePeeringDBNet converts /api/net?asn=N&depth=2 and places the exchanges
// and facilities using the bulk table (may be nil).
func ParsePeeringDBNet(b []byte, places *feeds.PeeringDB) (*PeeringDB, error) {
	var d struct {
		Data []pdbNet `json:"data"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("peeringdb: %w", err)
	}
	if len(d.Data) == 0 {
		return nil, nil
	}
	n := d.Data[0]
	p := &PeeringDB{ID: n.ID, Name: n.Name, AKA: n.AKA, Website: n.Website, Type: n.InfoType, Traffic: n.InfoTraffic,
		Ratio: n.InfoRatio, Scope: n.InfoScope, Prefixes4: n.InfoPrefixes4, Prefixes6: n.InfoPrefixes6, Policy: n.PolicyGeneral,
		PolicyURL: n.PolicyURL, PolicyLocations: n.PolicyLocations, PolicyContracts: n.PolicyContracts, IRRASSet: n.IRRASSet,
		IXCount: n.IXCount, FacCount: n.FacCount, Updated: n.Updated}
	ixIdx := map[int]int{}
	for _, l := range n.NetIXLan {
		i, ok := ixIdx[l.IXID]
		if !ok {
			name := l.Name
			if k := strings.Index(name, ": "); k > 0 && places == nil {
				name = name[:k]
			}
			x := IX{ID: l.IXID, Name: name}
			if places != nil {
				if pl := places.IX[l.IXID]; pl != nil {
					x.Name, x.City, x.Country, x.Lat, x.Lon = pl.Name, pl.City, pl.Country, pl.Lat, pl.Lon
				}
			}
			ixIdx[l.IXID] = len(p.IXs)
			p.IXs = append(p.IXs, x)
			i = len(p.IXs) - 1
		}
		x := &p.IXs[i]
		x.Ports++
		x.SpeedMb += l.Speed
		x.RSPeer = x.RSPeer || l.IsRSPeer
		x.Operates = x.Operates || l.Operational
		if x.IPv4 == "" {
			x.IPv4 = l.IPAddr4
		}
		if x.IPv6 == "" {
			x.IPv6 = l.IPAddr6
		}
	}
	seen := map[int]bool{}
	for _, f := range n.NetFac {
		if seen[f.FacID] {
			continue
		}
		seen[f.FacID] = true
		fc := Facility{ID: f.FacID, Name: f.Name, City: f.City, Country: f.Country}
		if places != nil {
			if pl := places.Fac[f.FacID]; pl != nil {
				fc.Lat, fc.Lon = pl.Lat, pl.Lon
			}
		}
		p.Facilities = append(p.Facilities, fc)
	}
	sort.SliceStable(p.IXs, func(i, j int) bool { return p.IXs[i].SpeedMb > p.IXs[j].SpeedMb })
	if p.IXCount == 0 {
		p.IXCount = len(p.IXs)
	}
	if p.FacCount == 0 {
		p.FacCount = len(p.Facilities)
	}
	return p, nil
}

// FromBulk builds the record from the weekly bulk dump (nil when the AS is
// not in it or the dump has no network part).
func FromBulk(db *feeds.PeeringDB, asn int) *PeeringDB {
	if db == nil || db.Nets == nil {
		return nil
	}
	n := db.Nets[asn]
	if n == nil {
		return nil
	}
	p := &PeeringDB{ID: n.ID, Name: n.Name, AKA: n.AKA, Website: n.Website, Type: n.Type, Traffic: n.Traffic, Ratio: n.Ratio,
		Scope: n.Scope, Prefixes4: n.Prefixes4, Prefixes6: n.Prefixes6, Policy: n.Policy, PolicyURL: n.PolicyURL,
		PolicyLocations: n.PolicyLocations, PolicyContracts: n.PolicyContracts, IRRASSet: n.IRRASSet,
		IXCount: n.IXCount, FacCount: n.FacCount, Updated: n.Updated}
	idx := map[int]int{}
	for _, port := range n.Ports {
		i, ok := idx[port.IX]
		if !ok {
			x := IX{ID: port.IX}
			if pl := db.IX[port.IX]; pl != nil {
				x.Name, x.City, x.Country, x.Lat, x.Lon = pl.Name, pl.City, pl.Country, pl.Lat, pl.Lon
			}
			idx[port.IX] = len(p.IXs)
			p.IXs = append(p.IXs, x)
			i = len(p.IXs) - 1
		}
		x := &p.IXs[i]
		x.Ports++
		x.SpeedMb += port.Speed
		x.RSPeer = x.RSPeer || port.RSPeer
		x.Operates = x.Operates || port.Up
		if x.IPv4 == "" {
			x.IPv4 = port.IPv4
		}
		if x.IPv6 == "" {
			x.IPv6 = port.IPv6
		}
	}
	seen := map[int]bool{}
	for _, id := range n.Facs {
		if seen[id] {
			continue
		}
		seen[id] = true
		f := Facility{ID: id}
		if pl := db.Fac[id]; pl != nil {
			f.Name, f.City, f.Country, f.Lat, f.Lon = pl.Name, pl.City, pl.Country, pl.Lat, pl.Lon
		}
		p.Facilities = append(p.Facilities, f)
	}
	sort.SliceStable(p.IXs, func(i, j int) bool { return p.IXs[i].SpeedMb > p.IXs[j].SpeedMb })
	if p.IXCount == 0 {
		p.IXCount = len(p.IXs)
	}
	if p.FacCount == 0 {
		p.FacCount = len(p.Facilities)
	}
	return p
}

// PeeringDBNet returns the network record: from the bulk feed when present,
// else from the API (cached 3 days; "not in PeeringDB" 1 day). A 429 is
// remembered for its Retry-After so later commands do not hammer the API.
func PeeringDBNet(ctx context.Context, asn int, offline bool) (*PeeringDB, bool, error) {
	places, _ := feeds.PDB(ctx)
	if places != nil && places.Nets != nil {
		if p := FromBulk(places, asn); p != nil {
			return p, true, nil
		}
		return nil, true, errSkip("not registered in PeeringDB")
	}
	key := strconv.Itoa(asn)
	var raw json.RawMessage
	cached := cache.Get("pdb-net", key, &raw)
	if !cached {
		if offline {
			return nil, false, errSkip("offline")
		}
		var until time.Time
		if cache.Get("pdb-block", "api", &until) && time.Now().Before(until) {
			return nil, false, fmt.Errorf("rate limited (HTTP 429) until %s; set PEERINGDB_API_KEY or run traced feeds update peeringdb later",
				until.Local().Format("15:04"))
		}
		hdr := map[string]string{}
		if k := os.Getenv("PEERINGDB_API_KEY"); k != "" {
			hdr["Authorization"] = "Api-Key " + k
		}
		var v json.RawMessage
		if err := do(ctx, "GET", fmt.Sprintf("%s/net?asn=%d&depth=2", PeeringDBURL, asn), nil, hdr, &v); err != nil {
			var he *httpError
			if errors.As(err, &he) && he.Code == 429 {
				d := he.RetryAfter
				if d <= 0 || d > 2*time.Hour {
					d = 10 * time.Minute
				}
				cache.Put("pdb-block", "api", time.Now().Add(d), d)
			}
			return nil, false, err
		}
		raw = v
		ttl := 3 * 24 * time.Hour
		if bytes.Contains(raw, []byte(`"data": []`)) || bytes.Contains(raw, []byte(`"data":[]`)) {
			ttl = 24 * time.Hour
		}
		cache.Put("pdb-net", key, raw, ttl)
	}
	p, err := ParsePeeringDBNet(raw, places)
	if err != nil {
		return nil, cached, err
	}
	if p == nil {
		return nil, cached, errSkip("not registered in PeeringDB")
	}
	return p, cached, nil
}

// ---------------- CAIDA AS Rank ----------------

const caidaQuery = `query($asn:String!){ asn(asn:$asn){ asn asnName rank organization{orgName orgId} country{iso name} cliqueMember latitude longitude cone{numberAsns numberPrefixes numberAddresses} asnDegree{provider peer customer total transit sibling} } }`

// ParseCAIDA converts the GraphQL answer.
func ParseCAIDA(b []byte) (*Rank, error) {
	var d struct {
		Data struct {
			ASN *struct {
				ASN          string `json:"asn"`
				Name         string `json:"asnName"`
				Rank         int    `json:"rank"`
				Organization *struct {
					OrgName string `json:"orgName"`
					OrgID   string `json:"orgId"`
				} `json:"organization"`
				Country *struct {
					ISO  string `json:"iso"`
					Name string `json:"name"`
				} `json:"country"`
				Clique bool    `json:"cliqueMember"`
				Lat    float64 `json:"latitude"`
				Lon    float64 `json:"longitude"`
				Cone   *struct {
					ASNs      int   `json:"numberAsns"`
					Prefixes  int   `json:"numberPrefixes"`
					Addresses int64 `json:"numberAddresses"`
				} `json:"cone"`
				Degree *struct {
					Provider, Peer, Customer, Total, Transit, Sibling int
				} `json:"asnDegree"`
			} `json:"asn"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("caida: %w", err)
	}
	if d.Data.ASN == nil {
		if len(d.Errors) > 0 {
			return nil, errors.New("caida: " + d.Errors[0].Message)
		}
		return nil, nil
	}
	a := d.Data.ASN
	r := &Rank{Rank: a.Rank, Name: a.Name, Clique: a.Clique, Lat: a.Lat, Lon: a.Lon}
	if a.Organization != nil {
		r.Org = a.Organization.OrgName
	}
	if a.Country != nil {
		r.Country, r.CountryName = a.Country.ISO, a.Country.Name
	}
	if a.Cone != nil {
		r.ConeASNs, r.ConePrefixes, r.ConeAddresses = a.Cone.ASNs, a.Cone.Prefixes, a.Cone.Addresses
	}
	if a.Degree != nil {
		r.Providers, r.Peers, r.Customers, r.Siblings, r.Degree = a.Degree.Provider, a.Degree.Peer, a.Degree.Customer, a.Degree.Sibling, a.Degree.Total
	}
	// the API sets cliqueMember on almost every AS; only a transit-free AS
	// (no providers at all) is shown as part of the tier-1 clique
	r.Clique = a.Clique && a.Degree != nil && a.Degree.Provider == 0
	return r, nil
}

// CAIDARank queries AS Rank (cached 7 days).
func CAIDARank(ctx context.Context, asn int, offline bool) (*Rank, bool, error) {
	key := strconv.Itoa(asn)
	var raw json.RawMessage
	cached := cache.Get("caida", key, &raw)
	if !cached {
		if offline {
			return nil, false, errSkip("offline")
		}
		body, _ := json.Marshal(map[string]any{"query": caidaQuery, "variables": map[string]string{"asn": key}})
		var v json.RawMessage
		if err := do(ctx, "POST", CAIDAURL, body, map[string]string{"Content-Type": "application/json"}, &v); err != nil {
			return nil, false, err
		}
		raw = v
		cache.Put("caida", key, raw, 7*24*time.Hour)
	}
	r, err := ParseCAIDA(raw)
	if err != nil {
		return nil, cached, err
	}
	if r == nil {
		return nil, cached, errSkip("not ranked by CAIDA")
	}
	return r, cached, nil
}

// ---------------- RIPEstat ----------------

func ripeGet(ctx context.Context, call string, asn int, ttl time.Duration, offline bool, v any) (bool, error) {
	key := call + "/" + strconv.Itoa(asn)
	var raw json.RawMessage
	if cache.Get("ripestat", key, &raw) {
		return true, json.Unmarshal(raw, v)
	}
	if offline {
		return false, errSkip("offline")
	}
	var x json.RawMessage
	url := fmt.Sprintf("%s/%s/data.json?resource=AS%d&sourceapp=traced-cli", RIPEstatURL, call, asn)
	if err := do(ctx, "GET", url, nil, nil, &x); err != nil {
		return false, err
	}
	cache.Put("ripestat", key, x, ttl)
	return false, json.Unmarshal(x, v)
}

// ParseAnnounced extracts the prefix lists from announced-prefixes.
func ParseAnnounced(b []byte) (v4, v6 []string, window string, err error) {
	var d struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
			Start string `json:"query_starttime"`
			End   string `json:"query_endtime"`
		} `json:"data"`
	}
	if err = json.Unmarshal(b, &d); err != nil {
		return
	}
	for _, p := range d.Data.Prefixes {
		pp, e := netip.ParsePrefix(p.Prefix)
		if e != nil {
			continue
		}
		if pp.Addr().Is4() {
			v4 = append(v4, pp.Masked().String())
		} else {
			v6 = append(v6, pp.Masked().String())
		}
	}
	sortPrefixes(v4)
	sortPrefixes(v6)
	if d.Data.Start != "" {
		window = d.Data.Start[:min(10, len(d.Data.Start))] + " … " + d.Data.End[:min(10, len(d.Data.End))]
	}
	return
}

func sortPrefixes(v []string) {
	sort.Slice(v, func(i, j int) bool {
		a, _ := netip.ParsePrefix(v[i])
		b, _ := netip.ParsePrefix(v[j])
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

// AddressCount sums the address space of v4 prefixes, not counting a prefix
// inside an already counted one.
func AddressCount(v4 []string) int64 {
	ps := make([]netip.Prefix, 0, len(v4))
	for _, s := range v4 {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
			ps = append(ps, p.Masked())
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	var n int64
	var last netip.Prefix
	for _, p := range ps {
		if last.IsValid() && last.Contains(p.Addr()) {
			continue
		}
		n += int64(1) << (32 - p.Bits())
		last = p
	}
	return n
}

// Prefixes returns the announced prefixes of asn (cached 12 h).
func Prefixes(ctx context.Context, asn int, offline bool) (v4, v6 []string, cached bool, err error) {
	var raw json.RawMessage
	cached, err = ripeGet(ctx, "announced-prefixes", asn, 12*time.Hour, offline, &raw)
	if err != nil {
		return
	}
	v4, v6, _, err = ParseAnnounced(raw)
	return
}

// ParseNeighbours extracts counts and the strongest upstream-side neighbours.
func ParseNeighbours(b []byte, top int) (left, right, unc int, ups []Neighbour, err error) {
	var d struct {
		Data struct {
			Counts struct {
				Left      int `json:"left"`
				Right     int `json:"right"`
				Uncertain int `json:"uncertain"`
			} `json:"neighbour_counts"`
			Neighbours []Neighbour `json:"neighbours"`
		} `json:"data"`
	}
	if err = json.Unmarshal(b, &d); err != nil {
		return
	}
	for _, n := range d.Data.Neighbours {
		if n.Type == "left" {
			ups = append(ups, n)
		}
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].Power > ups[j].Power })
	if len(ups) > top {
		ups = ups[:top]
	}
	return d.Data.Counts.Left, d.Data.Counts.Right, d.Data.Counts.Uncertain, ups, nil
}

// RIPE collects the routing view.
func RIPE(ctx context.Context, asn int, o Options) (*Routing, bool, error) {
	r := &Routing{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errs []error
	allCached := true
	run := func(fn func() (bool, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := fn()
			mu.Lock()
			defer mu.Unlock()
			allCached = allCached && c
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	run(func() (bool, error) {
		var raw json.RawMessage
		c, err := ripeGet(ctx, "announced-prefixes", asn, 12*time.Hour, o.NoNetwork, &raw)
		if err != nil {
			return c, fmt.Errorf("announced-prefixes: %s", describe(err, ctx))
		}
		v4, v6, win, err := ParseAnnounced(raw)
		if err != nil {
			return c, err
		}
		mu.Lock()
		r.V4, r.V6, r.CountV4, r.CountV6, r.PrefixesFrom = v4, v6, len(v4), len(v6), win
		if r.AddressesV4 == 0 {
			r.AddressesV4 = AddressCount(v4)
		}
		mu.Unlock()
		return c, nil
	})
	run(func() (bool, error) {
		var d struct {
			Data struct {
				Holder string `json:"holder"`
			} `json:"data"`
		}
		c, err := ripeGet(ctx, "as-overview", asn, 7*24*time.Hour, o.NoNetwork, &d)
		if err == nil {
			mu.Lock()
			r.Holder = d.Data.Holder
			mu.Unlock()
		}
		return c, nil // the holder name is cosmetic
	})
	if o.Neighbours {
		run(func() (bool, error) {
			var raw json.RawMessage
			c, err := ripeGet(ctx, "asn-neighbours", asn, 24*time.Hour, o.NoNetwork, &raw)
			if err != nil {
				return c, fmt.Errorf("asn-neighbours: %s", describe(err, ctx))
			}
			l, rr, u, ups, err := ParseNeighbours(raw, 10)
			if err != nil {
				return c, err
			}
			mu.Lock()
			r.Left, r.Right, r.Uncertain, r.Upstreams = l, rr, u, ups
			mu.Unlock()
			return c, nil
		})
	}
	if o.Visibility {
		run(func() (bool, error) {
			var d struct {
				Data struct {
					FirstSeen *struct {
						Time string `json:"time"`
					} `json:"first_seen"`
					Visibility struct {
						V4 struct {
							Seeing int `json:"ris_peers_seeing"`
							Total  int `json:"total_ris_peers"`
						} `json:"v4"`
						V6 struct {
							Seeing int `json:"ris_peers_seeing"`
							Total  int `json:"total_ris_peers"`
						} `json:"v6"`
					} `json:"visibility"`
					Space struct {
						V4 struct {
							IPs int64 `json:"ips"`
						} `json:"v4"`
						V6 struct {
							S48 int64 `json:"48s"`
						} `json:"v6"`
					} `json:"announced_space"`
				} `json:"data"`
			}
			c, err := ripeGet(ctx, "routing-status", asn, 6*time.Hour, o.NoNetwork, &d)
			if err != nil {
				return c, fmt.Errorf("routing-status: %s", describe(err, ctx))
			}
			mu.Lock()
			v := d.Data.Visibility
			r.VisV4Seeing, r.VisV4Total, r.VisV6Seeing, r.VisV6Total = v.V4.Seeing, v.V4.Total, v.V6.Seeing, v.V6.Total
			if d.Data.Space.V4.IPs > 0 {
				r.AddressesV4 = d.Data.Space.V4.IPs
			}
			r.Slash48sV6 = d.Data.Space.V6.S48
			if d.Data.FirstSeen != nil {
				r.FirstSeen = d.Data.FirstSeen.Time
			}
			mu.Unlock()
			return c, nil
		})
	}
	wg.Wait()
	if !o.Prefixes {
		r.V4, r.V6 = nil, nil
	}
	if len(errs) > 0 {
		msg := make([]string, len(errs))
		for i, e := range errs {
			msg[i] = e.Error()
		}
		sort.Strings(msg)
		if r.CountV4+r.CountV6 == 0 && r.Holder == "" && r.Left == 0 && r.VisV4Total == 0 {
			return nil, allCached, errors.New(strings.Join(msg, "; "))
		}
		return r, allCached, partialErr(strings.Join(msg, "; "))
	}
	return r, allCached, nil
}

type partialErr string

func (e partialErr) Error() string { return "partial: " + string(e) }

// ---------------- brief for the map ----------------

// Brief is the compact profile attached to traces (map hop cards, IX/PoP layer).
type Brief struct {
	ASN         int       `json:"asn"`
	Name        string    `json:"name,omitempty"`
	Org         string    `json:"org,omitempty"`
	Country     string    `json:"country,omitempty"`
	Rank        int       `json:"rank,omitempty"`
	Clique      bool      `json:"clique,omitempty"`
	ConeASNs    int       `json:"cone_asns,omitempty"`
	ConePfx     int       `json:"cone_prefixes,omitempty"`
	Providers   int       `json:"providers,omitempty"`
	Peers       int       `json:"peers,omitempty"`
	Customers   int       `json:"customers,omitempty"`
	Type        string    `json:"type,omitempty"`
	Traffic     string    `json:"traffic,omitempty"`
	Ratio       string    `json:"ratio,omitempty"`
	Policy      string    `json:"policy,omitempty"`
	IXCount     int       `json:"ix_count,omitempty"`
	FacCount    int       `json:"fac_count,omitempty"`
	PrefixesV4  int       `json:"prefixes_v4,omitempty"`
	PrefixesV6  int       `json:"prefixes_v6,omitempty"`
	AddressesV4 int64     `json:"addresses_v4,omitempty"`
	Users       int64     `json:"users,omitempty"`
	UsersCC     string    `json:"users_cc,omitempty"`
	UsersPctCC  float64   `json:"users_pct_cc,omitempty"`
	UsersPctW   float64   `json:"users_pct_world,omitempty"`
	Rep         string    `json:"rep,omitempty"` // Clean / Low risk / Suspicious / Dirty
	RepScore    int       `json:"rep_score,omitempty"`
	RepNotes    []string  `json:"rep_notes,omitempty"`
	PoPs        []PoP     `json:"pops,omitempty"`
	Errors      []string  `json:"errors,omitempty"`
	Fetched     time.Time `json:"fetched,omitempty"`
}

// PoP is a located exchange or facility of the AS.
type PoP struct {
	Kind    string  `json:"kind"` // ix | fac
	Name    string  `json:"name"`
	City    string  `json:"city,omitempty"`
	Country string  `json:"cc,omitempty"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	SpeedMb int     `json:"speed_mbps,omitempty"`
}

// BriefOf condenses a report. near (lat,lon pairs) sorts the PoPs so the ones
// close to the traced path come first; at most maxPoPs are kept.
func BriefOf(r *Report, near [][2]float64, maxPoPs int) *Brief {
	if r == nil {
		return nil
	}
	b := &Brief{ASN: r.ASN, Name: r.Name, Country: r.Country, Fetched: time.Now().UTC().Truncate(time.Second)}
	if k := r.Rank; k != nil {
		b.Rank, b.Clique, b.ConeASNs, b.ConePfx, b.Providers, b.Peers, b.Customers, b.Org = k.Rank, k.Clique, k.ConeASNs, k.ConePrefixes, k.Providers, k.Peers, k.Customers, k.Org
	}
	if p := r.PeeringDB; p != nil {
		b.Type, b.Traffic, b.Ratio, b.Policy, b.IXCount, b.FacCount = p.Type, p.Traffic, p.Ratio, p.Policy, p.IXCount, p.FacCount
		for _, x := range p.IXs {
			if x.Lat != 0 || x.Lon != 0 {
				b.PoPs = append(b.PoPs, PoP{Kind: "ix", Name: x.Name, City: x.City, Country: x.Country, Lat: x.Lat, Lon: x.Lon, SpeedMb: x.SpeedMb})
			}
		}
		for _, f := range p.Facilities {
			if f.Lat != 0 || f.Lon != 0 {
				b.PoPs = append(b.PoPs, PoP{Kind: "fac", Name: f.Name, City: f.City, Country: f.Country, Lat: f.Lat, Lon: f.Lon})
			}
		}
	}
	if rt := r.Routing; rt != nil {
		b.PrefixesV4, b.PrefixesV6, b.AddressesV4 = rt.CountV4, rt.CountV6, rt.AddressesV4
	}
	if e := r.Eyeballs; e != nil && len(e.Top) > 0 {
		b.Users, b.UsersPctW = e.Users, e.PctWorld
		b.UsersCC, b.UsersPctCC = e.Top[0].CC, e.Top[0].PctCountry
	}
	for _, s := range r.Sources {
		if s.Error != "" {
			b.Errors = append(b.Errors, s.Name+": "+s.Error)
		}
	}
	if len(near) > 0 && len(b.PoPs) > 0 {
		dist := func(p PoP) float64 {
			m := math.Inf(1)
			for _, q := range near {
				m = math.Min(m, feeds.HaversineKm(p.Lat, p.Lon, q[0], q[1]))
			}
			return m
		}
		sort.SliceStable(b.PoPs, func(i, j int) bool { return dist(b.PoPs[i]) < dist(b.PoPs[j]) })
	}
	if maxPoPs > 0 && len(b.PoPs) > maxPoPs {
		b.PoPs = b.PoPs[:maxPoPs]
	}
	return b
}
