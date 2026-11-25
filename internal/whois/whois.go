// Package whois implements RDAP and classic WHOIS (port 43) lookups for
// domains and IP addresses, DNS record collection and ASN lookups.
package whois

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
)

// UserAgent sent with every HTTP request.
var UserAgent = "traced-cli/1 (+https://github.com/PalMeany/traced-cli)"

var httpClient = &http.Client{Timeout: 12 * time.Second}

// DomainInfo is the registration data of a domain.
type DomainInfo struct {
	Domain      string   `json:"domain"`
	Source      string   `json:"source"` // rdap | whois
	Server      string   `json:"server,omitempty"`
	Registrar   string   `json:"registrar,omitempty"`
	Registrant  string   `json:"registrant,omitempty"`
	Created     string   `json:"created,omitempty"`
	Updated     string   `json:"updated,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Status      []string `json:"status,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	DNSSEC      string   `json:"dnssec,omitempty"`
}

// IPInfo is the registration data of an IP network.
type IPInfo struct {
	IP       string   `json:"ip"`
	Source   string   `json:"source"`
	Handle   string   `json:"handle,omitempty"`
	NetName  string   `json:"netname,omitempty"`
	Type     string   `json:"type,omitempty"`
	Country  string   `json:"country,omitempty"`
	Org      string   `json:"org,omitempty"`
	Range    string   `json:"range,omitempty"`
	CIDRs    []string `json:"cidrs,omitempty"`
	RIR      string   `json:"rir,omitempty"`
	Abuse    string   `json:"abuse,omitempty"`
	Geofeed  string   `json:"geofeed,omitempty"`
	ASN      int      `json:"asn,omitempty"`
	ASName   string   `json:"as_name,omitempty"`
	ASPrefix string   `json:"as_prefix,omitempty"`
	Created  string   `json:"created,omitempty"`
	Updated  string   `json:"updated,omitempty"`
}

// DNSInfo holds the resolved records of a name.
type DNSInfo struct {
	CNAME string   `json:"cname,omitempty"`
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	NS    []string `json:"ns,omitempty"`
	MX    []string `json:"mx,omitempty"`
	TXT   []string `json:"txt,omitempty"`
}

// Report bundles everything known about a target.
type Report struct {
	Query  string      `json:"query"`
	Domain *DomainInfo `json:"domain,omitempty"`
	DNS    *DNSInfo    `json:"dns,omitempty"`
	IPs    []*IPInfo   `json:"ips,omitempty"`
	Errors []string    `json:"errors,omitempty"`
}

// ---------------- RDAP ----------------

type rdapEntity struct {
	Roles     []string                            `json:"roles"`
	Handle    string                              `json:"handle"`
	VCard     json.RawMessage                     `json:"vcardArray"`
	Entities  []rdapEntity                        `json:"entities"`
	PublicIDs []struct{ Type, Identifier string } `json:"publicIds"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapDoc struct {
	ObjectClassName string       `json:"objectClassName"`
	LDHName         string       `json:"ldhName"`
	Handle          string       `json:"handle"`
	Name            string       `json:"name"`
	Type            string       `json:"type"`
	Country         string       `json:"country"`
	StartAddress    string       `json:"startAddress"`
	EndAddress      string       `json:"endAddress"`
	Status          []string     `json:"status"`
	Port43          string       `json:"port43"`
	Events          []rdapEvent  `json:"events"`
	Entities        []rdapEntity `json:"entities"`
	Nameservers     []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	CIDRs []struct {
		V4 string `json:"v4prefix"`
		V6 string `json:"v6prefix"`
		L  int    `json:"length"`
	} `json:"cidr0_cidrs"`
	ErrorCode int `json:"errorCode"`
}

func rdapGet(ctx context.Context, url string) (*rdapDoc, string, error) {
	var raw string
	if cache.Get("rdap", url, &raw) {
		var d rdapDoc
		if json.Unmarshal([]byte(raw), &d) == nil {
			return &d, raw, nil
		}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("rdap %s: %s", url, resp.Status)
	}
	var d rdapDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, "", fmt.Errorf("rdap: bad json: %v", err)
	}
	cache.Put("rdap", url, string(b), 3*24*time.Hour)
	return &d, string(b), nil
}

// vcardField extracts a property ("fn", "org", "email") from a jCard.
func vcardField(raw json.RawMessage, prop string) string {
	if len(raw) == 0 {
		return ""
	}
	var v []any
	if json.Unmarshal(raw, &v) != nil || len(v) < 2 {
		return ""
	}
	props, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		arr, ok := p.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		if name, _ := arr[0].(string); name == prop {
			switch val := arr[3].(type) {
			case string:
				return val
			case []any:
				var parts []string
				for _, x := range val {
					if s, ok := x.(string); ok && s != "" {
						parts = append(parts, s)
					}
				}
				return strings.Join(parts, " ")
			}
		}
	}
	return ""
}

func findEntity(ents []rdapEntity, role string) *rdapEntity {
	for i := range ents {
		for _, r := range ents[i].Roles {
			if r == role {
				return &ents[i]
			}
		}
	}
	for i := range ents {
		if e := findEntity(ents[i].Entities, role); e != nil {
			return e
		}
	}
	return nil
}

func entityName(e *rdapEntity) string {
	if e == nil {
		return ""
	}
	if s := vcardField(e.VCard, "fn"); s != "" {
		return s
	}
	if s := vcardField(e.VCard, "org"); s != "" {
		return s
	}
	return e.Handle
}

func eventDate(evs []rdapEvent, actions ...string) string {
	for _, a := range actions {
		for _, e := range evs {
			if e.Action == a {
				return e.Date
			}
		}
	}
	return ""
}

// ParseRDAPDomain converts an RDAP domain document.
func ParseRDAPDomain(d *rdapDoc) *DomainInfo {
	di := &DomainInfo{Domain: strings.ToLower(d.LDHName), Source: "rdap", Status: d.Status}
	di.Registrar = entityName(findEntity(d.Entities, "registrar"))
	di.Registrant = entityName(findEntity(d.Entities, "registrant"))
	di.Created = eventDate(d.Events, "registration")
	di.Updated = eventDate(d.Events, "last changed", "last update of RDAP database")
	di.Expires = eventDate(d.Events, "expiration")
	for _, ns := range d.Nameservers {
		di.Nameservers = append(di.Nameservers, strings.ToLower(ns.LDHName))
	}
	if d.SecureDNS != nil {
		if d.SecureDNS.DelegationSigned {
			di.DNSSEC = "signed"
		} else {
			di.DNSSEC = "unsigned"
		}
	}
	return di
}

// ParseRDAPDomainJSON parses raw RDAP JSON (exported for tests).
func ParseRDAPDomainJSON(b []byte) (*DomainInfo, error) {
	var d rdapDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return ParseRDAPDomain(&d), nil
}

// ParseRDAPIPJSON parses raw RDAP IP JSON (exported for tests).
func ParseRDAPIPJSON(ip string, b []byte) (*IPInfo, error) {
	var d rdapDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return parseRDAPIP(ip, &d, string(b)), nil
}

func parseRDAPIP(ip string, d *rdapDoc, raw string) *IPInfo {
	in := &IPInfo{IP: ip, Source: "rdap", Handle: d.Handle, NetName: d.Name, Type: d.Type, Country: d.Country}
	if d.StartAddress != "" {
		in.Range = d.StartAddress + " - " + d.EndAddress
	}
	for _, c := range d.CIDRs {
		p := c.V4
		if p == "" {
			p = c.V6
		}
		if p != "" {
			in.CIDRs = append(in.CIDRs, fmt.Sprintf("%s/%d", p, c.L))
		}
	}
	org := findEntity(d.Entities, "registrant")
	in.Org = entityName(org)
	if ab := findEntity(d.Entities, "abuse"); ab != nil {
		in.Abuse = vcardField(ab.VCard, "email")
	}
	in.RIR = rirFromPort43(d.Port43)
	in.Created = eventDate(d.Events, "registration")
	in.Updated = eventDate(d.Events, "last changed")
	in.Geofeed = ExtractGeofeedURL(raw)
	return in
}

func rirFromPort43(p string) string {
	p = strings.ToLower(p)
	for _, r := range []string{"ripe", "arin", "apnic", "lacnic", "afrinic"} {
		if strings.Contains(p, r) {
			return strings.ToUpper(r)
		}
	}
	return ""
}

var geofeedURLRe = regexp.MustCompile(`(?i)geofeed:?\s*"?\s*(https://[^\s"',\\]+)`)
var geofeedRelRe = regexp.MustCompile(`\{[^{}]*"rel"\s*:\s*"geofeed"[^{}]*\}`)
var hrefRe = regexp.MustCompile(`"href"\s*:\s*"(https://[^"]+)"`)

// ExtractGeofeedURL finds the RFC 9632 geofeed link in an RDAP/WHOIS document:
// a "geofeed:" attribute, a "Geofeed https://..." remark, or an RDAP link
// object with rel="geofeed".
func ExtractGeofeedURL(doc string) string {
	if m := geofeedURLRe.FindStringSubmatch(doc); m != nil {
		return strings.TrimRight(m[1], ".;)")
	}
	if blk := geofeedRelRe.FindString(doc); blk != "" {
		if m := hrefRe.FindStringSubmatch(blk); m != nil {
			return m[1]
		}
	}
	return ""
}

// ---------------- WHOIS :43 ----------------

// Query43 sends a raw WHOIS query.
func Query43(ctx context.Context, server, q string) (string, error) {
	if !strings.Contains(server, ":") {
		server += ":43"
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := fmt.Fprintf(c, "%s\r\n", q); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(c, 1<<20))
	if len(b) > 0 {
		return string(b), nil
	}
	return "", err
}

// ParseWhoisText extracts "key: value" pairs (keys lower-cased, values in order).
func ParseWhoisText(s string) map[string][]string {
	m := map[string][]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "%") || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ">>>") {
			continue
		}
		i := strings.Index(l, ":")
		if i <= 0 || i > 50 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(l[:i]))
		v := strings.TrimSpace(l[i+1:])
		if v == "" {
			continue
		}
		m[k] = append(m[k], v)
	}
	return m
}

func first(m map[string][]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// ParseWhoisDomain converts WHOIS text into DomainInfo.
func ParseWhoisDomain(domain, text string) *DomainInfo {
	m := ParseWhoisText(text)
	di := &DomainInfo{Domain: domain, Source: "whois"}
	di.Registrar = first(m, "registrar", "sponsoring registrar", "registrar name")
	di.Registrant = first(m, "registrant organization", "registrant organisation", "org", "registrant", "registrant name")
	di.Created = first(m, "creation date", "created", "registered on", "registration time", "created on", "domain registration date")
	di.Updated = first(m, "updated date", "last updated", "changed", "last-update", "last modified")
	di.Expires = first(m, "registry expiry date", "registrar registration expiration date", "expiration date", "expiry date", "paid-till", "expires", "expires on", "expire date")
	seen := map[string]bool{}
	for _, k := range []string{"name server", "nserver", "nameserver", "nameservers"} {
		for _, v := range m[k] {
			ns := strings.ToLower(strings.Fields(v)[0])
			ns = strings.TrimSuffix(ns, ".")
			if !seen[ns] {
				seen[ns] = true
				di.Nameservers = append(di.Nameservers, ns)
			}
		}
	}
	for _, k := range []string{"domain status", "status", "state"} {
		for _, v := range m[k] {
			di.Status = append(di.Status, strings.Fields(v)[0])
		}
	}
	di.DNSSEC = first(m, "dnssec")
	return di
}

// ParseWhoisIP converts WHOIS text into IPInfo.
func ParseWhoisIP(ip, text string) *IPInfo {
	m := ParseWhoisText(text)
	in := &IPInfo{IP: ip, Source: "whois"}
	in.NetName = first(m, "netname", "net-name", "netname")
	in.Range = first(m, "inetnum", "inet6num", "netrange", "cidr")
	in.Country = strings.ToUpper(first(m, "country"))
	in.Org = first(m, "org-name", "orgname", "organization", "descr", "owner")
	in.Abuse = first(m, "abuse-mailbox", "orgabuseemail", "abuse-c")
	in.Geofeed = ExtractGeofeedURL(text)
	in.Created = first(m, "created", "regdate")
	in.Updated = first(m, "last-modified", "updated")
	return in
}

var referRe = regexp.MustCompile(`(?im)^(?:refer|whois):\s*(\S+)`)
var registrarWhoisRe = regexp.MustCompile(`(?im)^\s*Registrar WHOIS Server:\s*(\S+)`)

// WhoisDomain performs a referral-following WHOIS lookup.
func WhoisDomain(ctx context.Context, domain string) (*DomainInfo, string, error) {
	tld := domain[strings.LastIndex(domain, ".")+1:]
	server := ""
	if !cache.Get("whois-tld", tld, &server) {
		iana, err := Query43(ctx, "whois.iana.org", tld)
		if err != nil {
			return nil, "", err
		}
		if m := referRe.FindStringSubmatch(iana); m != nil {
			server = m[1]
			cache.Put("whois-tld", tld, server, 30*24*time.Hour)
		}
	}
	if server == "" {
		return nil, "", errors.New("no whois server for ." + tld)
	}
	text, err := Query43(ctx, server, domain)
	if err != nil {
		return nil, "", err
	}
	if m := registrarWhoisRe.FindStringSubmatch(text); m != nil && !strings.EqualFold(m[1], server) {
		if t2, err := Query43(ctx, m[1], domain); err == nil && len(t2) > 200 {
			di := ParseWhoisDomain(domain, t2)
			base := ParseWhoisDomain(domain, text)
			mergeDomain(di, base)
			di.Server = m[1]
			return di, t2, nil
		}
	}
	di := ParseWhoisDomain(domain, text)
	di.Server = server
	return di, text, nil
}

func mergeDomain(dst, src *DomainInfo) {
	if dst.Registrar == "" {
		dst.Registrar = src.Registrar
	}
	if dst.Created == "" {
		dst.Created = src.Created
	}
	if dst.Expires == "" {
		dst.Expires = src.Expires
	}
	if len(dst.Nameservers) == 0 {
		dst.Nameservers = src.Nameservers
	}
	if len(dst.Status) == 0 {
		dst.Status = src.Status
	}
}

// ---------------- high level ----------------

// LookupDomain tries RDAP, then WHOIS.
func LookupDomain(ctx context.Context, domain string) (*DomainInfo, error) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	reg := RegisteredDomain(domain)
	var di DomainInfo
	if cache.Get("domain", reg, &di) {
		return &di, nil
	}
	d, _, err := rdapGet(ctx, "https://rdap.org/domain/"+reg)
	if err == nil && d.LDHName != "" {
		r := ParseRDAPDomain(d)
		r.Server = "rdap.org"
		cache.Put("domain", reg, r, 24*time.Hour)
		return r, nil
	}
	w, _, werr := WhoisDomain(ctx, reg)
	if werr != nil {
		if err != nil {
			return nil, fmt.Errorf("rdap: %v; whois: %v", err, werr)
		}
		return nil, werr
	}
	cache.Put("domain", reg, w, 24*time.Hour)
	return w, nil
}

// LookupIP tries RDAP (with WHOIS fallback) and adds ASN data.
func LookupIP(ctx context.Context, ip string) (*IPInfo, error) {
	var in *IPInfo
	var cached IPInfo
	if cache.Get("ipinfo", ip, &cached) {
		return &cached, nil
	}
	d, raw, err := rdapGet(ctx, "https://rdap.org/ip/"+ip)
	if err == nil {
		in = parseRDAPIP(ip, d, raw)
	} else {
		srv := "whois.ripe.net"
		if t, werr := Query43(ctx, "whois.iana.org", ip); werr == nil {
			if m := referRe.FindStringSubmatch(t); m != nil {
				srv = m[1]
			}
		}
		text, werr := Query43(ctx, srv, ip)
		if werr != nil {
			return nil, fmt.Errorf("rdap: %v; whois: %v", err, werr)
		}
		in = ParseWhoisIP(ip, text)
		in.RIR = rirFromPort43(srv)
	}
	if as, err := LookupASN(ctx, net.ParseIP(ip)); err == nil && as != nil {
		in.ASN, in.ASName, in.ASPrefix = as.ASN, as.Name, as.Prefix
		if in.RIR == "" {
			in.RIR = strings.ToUpper(as.Registry)
		}
	}
	cache.Put("ipinfo", ip, in, 3*24*time.Hour)
	return in, nil
}

// LookupDNS collects A/AAAA/CNAME/NS/MX records (queries run in parallel,
// each bounded so a dead resolver cannot stall the report).
func LookupDNS(ctx context.Context, name string) *DNSInfo {
	r := net.DefaultResolver
	out := &DNSInfo{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	q := func(fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			fn(c)
		}()
	}
	q(func(c context.Context) {
		if cn, err := r.LookupCNAME(c, name); err == nil {
			cn = strings.TrimSuffix(cn, ".")
			if !strings.EqualFold(cn, strings.TrimSuffix(name, ".")) {
				mu.Lock()
				out.CNAME = cn
				mu.Unlock()
			}
		}
	})
	q(func(c context.Context) {
		if ips, err := r.LookupIPAddr(c, name); err == nil {
			mu.Lock()
			for _, ip := range ips {
				if ip.IP.To4() != nil {
					out.A = append(out.A, ip.IP.String())
				} else {
					out.AAAA = append(out.AAAA, ip.IP.String())
				}
			}
			mu.Unlock()
		}
	})
	q(func(c context.Context) {
		if ns, err := r.LookupNS(c, RegisteredDomain(name)); err == nil {
			var l []string
			for _, n := range ns {
				l = append(l, strings.TrimSuffix(n.Host, "."))
			}
			sort.Strings(l)
			mu.Lock()
			out.NS = l
			mu.Unlock()
		}
	})
	q(func(c context.Context) {
		if mx, err := r.LookupMX(c, name); err == nil {
			var l []string
			for _, m := range mx {
				l = append(l, fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, ".")))
			}
			mu.Lock()
			out.MX = l
			mu.Unlock()
		}
	})
	wg.Wait()
	return out
}

// Lookup builds a complete report for a domain or IP.
func Lookup(ctx context.Context, q string) *Report {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	q = strings.TrimSpace(q)
	rep := &Report{Query: q}
	if ip := net.ParseIP(q); ip != nil {
		in, err := LookupIP(ctx, ip.String())
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		} else {
			rep.IPs = append(rep.IPs, in)
		}
		return rep
	}
	type dres struct {
		d   *DomainInfo
		err error
	}
	dc := make(chan dres, 1)
	go func() {
		d, err := LookupDomain(ctx, q)
		dc <- dres{d, err}
	}()
	rep.DNS = LookupDNS(ctx, q)
	ips := append([]string{}, rep.DNS.A...)
	if len(rep.DNS.AAAA) > 0 {
		ips = append(ips, rep.DNS.AAAA[0])
	}
	if len(ips) > 3 {
		ips = ips[:3]
	}
	res := make([]*IPInfo, len(ips))
	done := make(chan struct{}, len(ips))
	for i, ip := range ips {
		go func(i int, ip string) {
			if in, err := LookupIP(ctx, ip); err == nil {
				res[i] = in
			}
			done <- struct{}{}
		}(i, ip)
	}
	for range ips {
		<-done
	}
	for _, r := range res {
		if r != nil {
			rep.IPs = append(rep.IPs, r)
		}
	}
	d := <-dc
	if d.err != nil {
		rep.Errors = append(rep.Errors, d.err.Error())
	} else {
		rep.Domain = d.d
	}
	return rep
}

// multi-label public suffixes we care about
var multiSuffix = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "com.ru": true, "net.ru": true, "org.ru": true, "msk.ru": true,
	"spb.ru": true, "com.ua": true, "co.jp": true, "ne.jp": true, "com.au": true, "net.au": true, "com.br": true,
	"com.cn": true, "com.tr": true, "co.kr": true, "co.in": true, "com.sg": true, "com.hk": true, "co.nz": true,
	"com.mx": true, "com.ar": true, "co.za": true, "com.pl": true, "eu.org": true, "github.io": true, "nuv.cx": false,
}

// RegisteredDomain returns the registrable part of a hostname (eTLD+1, approximated).
func RegisteredDomain(h string) string {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	p := strings.Split(h, ".")
	if len(p) <= 2 {
		return h
	}
	last2 := strings.Join(p[len(p)-2:], ".")
	if multiSuffix[last2] {
		return strings.Join(p[len(p)-3:], ".")
	}
	return last2
}

// ---------------- ASN (Team Cymru DNS) ----------------

// ASInfo describes the origin AS of an address.
type ASInfo struct {
	ASN      int    `json:"asn"`
	Prefix   string `json:"prefix,omitempty"`
	Country  string `json:"country,omitempty"`
	Registry string `json:"registry,omitempty"`
	Name     string `json:"name,omitempty"`
}

// ParseCymruOrigin parses "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11".
func ParseCymruOrigin(s string) *ASInfo {
	f := strings.Split(s, "|")
	if len(f) < 3 {
		return nil
	}
	asn, err := strconv.Atoi(strings.Fields(strings.TrimSpace(f[0]) + " 0")[0])
	if err != nil || asn == 0 {
		return nil
	}
	a := &ASInfo{ASN: asn, Prefix: strings.TrimSpace(f[1]), Country: strings.TrimSpace(f[2])}
	if len(f) > 3 {
		a.Registry = strings.TrimSpace(f[3])
	}
	return a
}

// ParseCymruName parses "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US".
func ParseCymruName(s string) string {
	f := strings.Split(s, "|")
	if len(f) < 5 {
		return ""
	}
	return strings.TrimSpace(f[4])
}

func reverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "%x.%x.", v6[i]&0xf, v6[i]>>4)
	}
	return b.String() + "origin6.asn.cymru.com"
}

// LookupASN resolves the origin AS via Team Cymru's DNS interface.
func LookupASN(ctx context.Context, ip net.IP) (*ASInfo, error) {
	if ip == nil {
		return nil, errors.New("bad ip")
	}
	var a ASInfo
	if cache.Get("asn", ip.String(), &a) {
		if a.ASN == 0 {
			return nil, nil
		}
		return &a, nil
	}
	ai, err := cymruASN(ctx, ip)
	if ai == nil {
		// DNS may be broken behind VPNs/split-DNS: fall back to RIPEstat over HTTPS
		if r, rerr := ripestatASN(ctx, ip); rerr == nil && r != nil {
			ai, err = r, nil
		}
	}
	if ai == nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			cache.Put("asn", ip.String(), ASInfo{}, 12*time.Hour)
		}
		return nil, err
	}
	name := ai.Name
	if name == "" && !cache.Get("asname", strconv.Itoa(ai.ASN), &name) {
		name = asName(ctx, ai.ASN)
		if name != "" {
			cache.Put("asname", strconv.Itoa(ai.ASN), name, 14*24*time.Hour)
		}
	}
	ai.Name = name
	cache.Put("asn", ip.String(), ai, 3*24*time.Hour)
	return ai, nil
}

func lookupTXT(ctx context.Context, name string) ([]string, error) {
	var last error
	for i := 0; i < 2; i++ {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		t, err := net.DefaultResolver.LookupTXT(c, name)
		cancel()
		if err == nil {
			return t, nil
		}
		last = err
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, err
		}
	}
	return nil, last
}

func cymruASN(ctx context.Context, ip net.IP) (*ASInfo, error) {
	txt, err := lookupTXT(ctx, reverseName(ip))
	if err != nil || len(txt) == 0 {
		return nil, err
	}
	return ParseCymruOrigin(txt[0]), nil
}

func asName(ctx context.Context, asn int) string {
	if t, err := lookupTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn)); err == nil && len(t) > 0 {
		if n := ParseCymruName(t[0]); n != "" {
			return n
		}
	}
	var r struct {
		Data struct {
			Holder string `json:"holder"`
		} `json:"data"`
	}
	if err := getJSON(ctx, fmt.Sprintf("https://stat.ripe.net/data/as-overview/data.json?resource=AS%d", asn), &r); err == nil {
		return r.Data.Holder
	}
	return ""
}

func ripestatASN(ctx context.Context, ip net.IP) (*ASInfo, error) {
	var r struct {
		Data struct {
			ASNs   []string `json:"asns"`
			Prefix string   `json:"prefix"`
		} `json:"data"`
	}
	if err := getJSON(ctx, "https://stat.ripe.net/data/network-info/data.json?resource="+ip.String(), &r); err != nil {
		return nil, err
	}
	if len(r.Data.ASNs) == 0 {
		return nil, nil
	}
	asn, err := strconv.Atoi(r.Data.ASNs[0])
	if err != nil || asn == 0 {
		return nil, nil
	}
	return &ASInfo{ASN: asn, Prefix: r.Data.Prefix}, nil
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
