// Package feeds downloads, caches and parses open network datasets: the
// TeleGeography submarine cable map, PeeringDB facilities/exchanges, APNIC
// Labs AS population, and reputation lists (Kinetio DTIH, Spamhaus DROP /
// ASN-DROP, FireHOL level1, Tor exit nodes, Emerging Threats). Everything is
// kept in ~/.cache/traced/feeds; a feed older than its TTL is refreshed on
// use and the previous copy keeps serving when the refresh fails.
package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
)

// UserAgent sent with every request.
var UserAgent = "traced-cli/1.2 (+https://github.com/PalMeany/traced-cli)"

// Kind of a feed's payload.
type Kind string

const (
	KindNetset    Kind = "netset"  // IP/CIDR per line
	KindKinetio   Kind = "kinetio" // DTIH JSON
	KindDROP      Kind = "drop"    // Spamhaus DROP NDJSON
	KindASNDrop   Kind = "asndrop" // Spamhaus ASN-DROP NDJSON
	KindASPop     Kind = "aspop"   // APNIC Labs AS population JSON
	KindCables    Kind = "cables"  // combined TeleGeography map (built)
	KindPeeringDB Kind = "peeringdb"
)

// Feed describes one dataset.
type Feed struct {
	Name     string
	Title    string
	URL      string
	Kind     Kind
	TTL      time.Duration
	Type     string // category given to netset entries ("tor-exit", "firehol-l1"…)
	Rep      bool   // used by the reputation check
	MaxBytes int64
	Budget   time.Duration // refresh-on-use time limit (default UpdateBudget)
	Info     string        // human description / terms
}

// All feeds, in display order.
var All = []*Feed{
	{Name: "kinetio", Title: "Kinetio DTIH public feed", URL: "https://dtih.kinetio.cc/feeds/v1/public?format=json",
		Kind: KindKinetio, TTL: 6 * time.Hour, Rep: true, MaxBytes: 64 << 20,
		Info: "scanners, brute force, recon, exploit attempts (addresses and subnets)"},
	{Name: "spamhaus-drop4", Title: "Spamhaus DROP IPv4", URL: "https://www.spamhaus.org/drop/drop_v4.json",
		Kind: KindDROP, TTL: 24 * time.Hour, Rep: true, MaxBytes: 8 << 20, Info: "hijacked / leased-to-criminals netblocks"},
	{Name: "spamhaus-drop6", Title: "Spamhaus DROP IPv6", URL: "https://www.spamhaus.org/drop/drop_v6.json",
		Kind: KindDROP, TTL: 24 * time.Hour, Rep: true, MaxBytes: 8 << 20},
	{Name: "spamhaus-asndrop", Title: "Spamhaus ASN-DROP", URL: "https://www.spamhaus.org/drop/asndrop.json",
		Kind: KindASNDrop, TTL: 24 * time.Hour, Rep: true, MaxBytes: 8 << 20, Info: "autonomous systems run by cybercriminals"},
	{Name: "firehol-l1", Title: "FireHOL level1", URL: "https://iplists.firehol.org/files/firehol_level1.netset",
		Kind: KindNetset, Type: "firehol-l1", TTL: 24 * time.Hour, Rep: true, MaxBytes: 16 << 20,
		Info: "aggregate of DROP, dshield, feodo, sslbl and bogons — safe to block"},
	{Name: "et-block", Title: "Emerging Threats block list", URL: "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
		Kind: KindNetset, Type: "et-block", TTL: 24 * time.Hour, Rep: true, MaxBytes: 8 << 20,
		Info: "ET compromised hosts + dshield top attackers"},
	{Name: "tor-exit", Title: "Tor exit nodes", URL: "https://check.torproject.org/torbulkexitlist",
		Kind: KindNetset, Type: "tor-exit", TTL: 6 * time.Hour, Rep: true, MaxBytes: 4 << 20,
		Info: "anonymity network exits (not abuse by itself)"},
	{Name: "aspop", Title: "APNIC Labs AS population (eyeballs)", URL: "https://stats.labs.apnic.net/cgi-bin/aspop?c=&f=j",
		Kind: KindASPop, TTL: 7 * 24 * time.Hour, MaxBytes: 64 << 20, Info: "slow server: the first download may take a minute"},
	{Name: "peeringdb", Title: "PeeringDB facilities & exchanges", URL: "https://www.peeringdb.com/api/",
		Kind: KindPeeringDB, TTL: 7 * 24 * time.Hour, MaxBytes: 400 << 20, Budget: 2 * time.Minute,
		Info: "networks, exchanges, facilities; falls back to the CAIDA daily dump when the API rate-limits"},
	{Name: "cables", Title: "TeleGeography submarine cables", URL: "https://www.submarinecablemap.com/api/v3/",
		Kind: KindCables, TTL: 7 * 24 * time.Hour, MaxBytes: 64 << 20, Budget: 2 * time.Minute,
		Info: "CC BY-NC-SA 3.0 TeleGeography (submarinecablemap.com)"},
}

// ByName finds a feed.
func ByName(name string) *Feed {
	for _, f := range All {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// Meta is stored next to each feed.
type Meta struct {
	URL          string    `json:"url"`
	Fetched      time.Time `json:"fetched,omitempty"` // last successful download
	Checked      time.Time `json:"checked,omitempty"` // last attempt (304 counts as success)
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Entries      int       `json:"entries"`
	Size         int64     `json:"size"`
	Error        string    `json:"error,omitempty"`
	ErrorAt      time.Time `json:"error_at,omitempty"`
}

// Status of a feed for `traced feeds`.
type Status struct {
	Name    string    `json:"name"`
	Title   string    `json:"title"`
	URL     string    `json:"url"`
	Path    string    `json:"path"`
	Present bool      `json:"present"`
	Fresh   bool      `json:"fresh"`
	Fetched time.Time `json:"fetched,omitempty"`
	Checked time.Time `json:"checked,omitempty"`
	TTL     string    `json:"ttl"`
	Entries int       `json:"entries"`
	Size    int64     `json:"size"`
	Error   string    `json:"error,omitempty"`
	Info    string    `json:"info,omitempty"`
}

var (
	httpClient = &http.Client{Timeout: 4 * time.Minute} // requests carry their own deadlines
	// AutoUpdate enables refresh-on-use of stale feeds (TRACED_FEEDS_AUTO=0 disables).
	AutoUpdate = os.Getenv("TRACED_FEEDS_AUTO") != "0"
	// UpdateBudget caps how long a refresh-on-use may block a command.
	UpdateBudget = 25 * time.Second
)

func dataPath(f *Feed) string { return cache.File("feeds", f.Name+".dat") }
func metaPath(f *Feed) string { return cache.File("feeds", f.Name+".meta.json") }

// Dir is the feed directory.
func Dir() string { return filepath.Join(cache.Dir(), "feeds") }

func readMeta(f *Feed) Meta {
	var m Meta
	if b, err := os.ReadFile(metaPath(f)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeMeta(f *Feed, m Meta) {
	b, _ := json.MarshalIndent(m, "", "  ")
	writeAtomic(metaPath(f), b)
}

func writeAtomic(p string, b []byte) error {
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	tmp := fmt.Sprintf("%s.%d.tmp", p, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// fresh: present and checked (downloaded or 304) within TTL.
func isFresh(f *Feed, m Meta) bool {
	if _, err := os.Stat(dataPath(f)); err != nil {
		return false
	}
	t := m.Checked
	if t.IsZero() {
		t = m.Fetched
	}
	return time.Since(t) < f.TTL
}

// Stat reports the state of every feed.
func Stat() []Status {
	var out []Status
	for _, f := range All {
		m := readMeta(f)
		st, err := os.Stat(dataPath(f))
		s := Status{Name: f.Name, Title: f.Title, URL: f.URL, Path: dataPath(f), Present: err == nil, Fresh: isFresh(f, m),
			Fetched: m.Fetched, Checked: m.Checked, TTL: f.TTL.String(), Entries: m.Entries, Error: m.Error, Info: f.Info}
		if err == nil {
			s.Size = st.Size()
		}
		out = append(out, s)
	}
	return out
}

var errNotModified = errors.New("not modified")

type httpErr struct {
	Code int
	URL  string
}

func (e *httpErr) Error() string { return fmt.Sprintf("%s: HTTP %d", e.URL, e.Code) }

// IsRateLimited reports a 429 (or 503 with backoff) answer.
func IsRateLimited(err error) bool {
	var he *httpErr
	return errors.As(err, &he) && (he.Code == 429 || he.Code == 503)
}

// get downloads url. With m it sends conditional headers and fills them back.
func get(ctx context.Context, url string, m *Meta, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if m != nil {
		if m.ETag != "" {
			req.Header.Set("If-None-Match", m.ETag)
		}
		if m.LastModified != "" {
			req.Header.Set("If-Modified-Since", m.LastModified)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && m != nil {
		return nil, errNotModified
	}
	if resp.StatusCode != 200 {
		return nil, &httpErr{resp.StatusCode, url}
	}
	if limit <= 0 {
		limit = 32 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d MB", url, limit>>20)
	}
	if m != nil {
		m.ETag = resp.Header.Get("ETag")
		m.LastModified = resp.Header.Get("Last-Modified")
	}
	return b, nil
}

// validate parses a payload and returns the number of records.
func validate(f *Feed, b []byte) (int, error) {
	switch f.Kind {
	case KindKinetio:
		e, err := ParseKinetio(b)
		if err == nil && len(e) == 0 {
			err = errors.New("no entries")
		}
		return len(e), err
	case KindDROP:
		e, err := ParseSpamhausDROP(b)
		if err == nil && len(e) == 0 {
			err = errors.New("no entries")
		}
		return len(e), err
	case KindASNDrop:
		e, err := ParseASNDrop(b)
		if err == nil && len(e) == 0 {
			err = errors.New("no entries")
		}
		return len(e), err
	case KindNetset:
		e, err := ParseNetset(bytes.NewReader(b), f.Type)
		if err == nil && len(e) == 0 {
			err = errors.New("no entries")
		}
		return len(e), err
	case KindASPop:
		m, _, err := ParseASPop(bytes.NewReader(b))
		return len(m), err
	case KindCables:
		var db CableDB
		if err := json.Unmarshal(b, &db); err != nil {
			return 0, err
		}
		if len(db.Cables) == 0 {
			return 0, errors.New("no cables")
		}
		return len(db.Cables), nil
	case KindPeeringDB:
		var db PeeringDB
		if err := json.Unmarshal(b, &db); err != nil {
			return 0, err
		}
		if len(db.Fac) == 0 {
			return 0, errors.New("no facilities")
		}
		return len(db.Fac) + len(db.IX) + len(db.Nets), nil
	}
	return 0, fmt.Errorf("unknown kind %s", f.Kind)
}

var (
	updMu    sync.Mutex
	updating = map[string]*updCall{}
)

type updCall struct {
	done chan struct{}
	res  Result
}

// Result of one feed update.
type Result struct {
	Name      string        `json:"name"`
	Updated   bool          `json:"updated"`   // new data stored
	Unchanged bool          `json:"unchanged"` // 304 / same data
	Entries   int           `json:"entries"`
	Took      time.Duration `json:"took"`
	Err       error         `json:"-"`
	Error     string        `json:"error,omitempty"`
}

// Update refreshes one feed now (concurrent calls for the same feed share one
// download). On failure the old copy is kept and the error recorded.
func Update(ctx context.Context, f *Feed) Result {
	updMu.Lock()
	if c, ok := updating[f.Name]; ok {
		updMu.Unlock()
		select {
		case <-c.done:
			return c.res
		case <-ctx.Done():
			return Result{Name: f.Name, Err: ctx.Err(), Error: ctx.Err().Error()}
		}
	}
	c := &updCall{done: make(chan struct{})}
	updating[f.Name] = c
	updMu.Unlock()
	c.res = doUpdate(ctx, f)
	updMu.Lock()
	delete(updating, f.Name)
	updMu.Unlock()
	close(c.done)
	return c.res
}

func doUpdate(ctx context.Context, f *Feed) Result {
	t0 := time.Now()
	m := readMeta(f)
	m.URL = f.URL
	r := Result{Name: f.Name}
	var b []byte
	var err error
	_, statErr := os.Stat(dataPath(f))
	cond := &m
	if statErr != nil {
		cond = &Meta{}
	}
	switch f.Kind {
	case KindCables:
		b, err = buildCables(ctx, f, cond)
	case KindPeeringDB:
		b, err = buildPeeringDB(ctx, f)
	default:
		b, err = get(ctx, f.URL, cond, f.MaxBytes)
	}
	if cond != &m {
		m.ETag, m.LastModified = cond.ETag, cond.LastModified
	}
	r.Took = time.Since(t0)
	if errors.Is(err, errNotModified) {
		m.Checked, m.Error = time.Now(), ""
		writeMeta(f, m)
		r.Unchanged, r.Entries = true, m.Entries
		return r
	}
	if err == nil {
		var n int
		n, err = validate(f, b)
		if err == nil {
			if err = writeAtomic(dataPath(f), b); err == nil {
				m.Fetched, m.Checked, m.Entries, m.Size, m.Error, m.ErrorAt = time.Now(), time.Now(), n, int64(len(b)), "", time.Time{}
				writeMeta(f, m)
				invalidate(f.Name)
				r.Updated, r.Entries = true, n
				return r
			}
		} else {
			err = fmt.Errorf("bad payload: %w", err)
		}
	}
	m.Error, m.ErrorAt = err.Error(), time.Now()
	// back off: a failed attempt counts as a check for a fraction of the TTL so
	// every command does not retry a dead source
	writeMeta(f, m)
	r.Err, r.Error, r.Entries = err, err.Error(), m.Entries
	return r
}

// UpdateAll refreshes the named feeds (all when names is empty); force
// ignores the TTL. Feeds are fetched in parallel.
func UpdateAll(ctx context.Context, names []string, force bool) ([]Result, error) {
	var list []*Feed
	if len(names) == 0 {
		list = All
	} else {
		for _, n := range names {
			f := ByName(n)
			if f == nil {
				return nil, fmt.Errorf("unknown feed %q (known: %s)", n, strings.Join(Names(), ", "))
			}
			list = append(list, f)
		}
	}
	out := make([]Result, len(list))
	var wg sync.WaitGroup
	for i, f := range list {
		wg.Add(1)
		go func(i int, f *Feed) {
			defer wg.Done()
			if !force && isFresh(f, readMeta(f)) {
				m := readMeta(f)
				out[i] = Result{Name: f.Name, Unchanged: true, Entries: m.Entries}
				return
			}
			out[i] = Update(ctx, f)
		}(i, f)
	}
	wg.Wait()
	return out, nil
}

// Names of all feeds.
func Names() []string {
	var n []string
	for _, f := range All {
		n = append(n, f.Name)
	}
	return n
}

// ensure makes sure the feed is present and (when AutoUpdate) not stale.
// It returns the raw bytes of whatever copy is available and a note when the
// copy is stale or missing.
func ensure(ctx context.Context, f *Feed) ([]byte, string) {
	m := readMeta(f)
	bg := false
	if AutoUpdate && !isFresh(f, m) && !recentFailure(f, m) {
		// the download runs on its own deadline; the caller waits at most
		// UpdateBudget (or until its context ends) and otherwise goes on with
		// the old copy while the refresh finishes in the background
		budget := 3 * time.Minute
		if f.Budget > budget {
			budget = f.Budget
		}
		done := make(chan Result, 1)
		go func() {
			c, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			done <- Update(c, f)
		}()
		wait := UpdateBudget
		if f.Budget > 0 && f.Budget < wait {
			wait = f.Budget
		}
		t := time.NewTimer(wait)
		select {
		case <-done:
		case <-t.C:
			bg = true
		case <-ctx.Done():
			bg = true
		}
		t.Stop()
		m = readMeta(f)
	}
	b, err := os.ReadFile(dataPath(f))
	if err != nil {
		if m.Error != "" {
			return nil, fmt.Sprintf("%s unavailable: %s", f.Name, m.Error)
		}
		return nil, f.Name + " not downloaded (traced feeds update)"
	}
	m = readMeta(f)
	if !isFresh(f, m) {
		if bg {
			return b, f.Name + " is stale, refreshing in the background"
		}
		age := time.Since(m.Fetched).Round(time.Hour)
		if m.Fetched.IsZero() {
			return b, f.Name + " is stale"
		}
		return b, fmt.Sprintf("%s is %s old (refresh failed: %s)", f.Name, age, orStr(m.Error, "auto-update off"))
	}
	return b, ""
}

// recentFailure: do not hammer a failing source more than every 15 min.
func recentFailure(f *Feed, m Meta) bool {
	return !m.ErrorAt.IsZero() && time.Since(m.ErrorAt) < 15*time.Minute
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ---------------- parsed, memoised views ----------------

type memo struct {
	v    any
	note string
	at   time.Time
}

var (
	memoMu sync.Mutex
	memos  = map[string]*memo{}
	locks  = map[string]*sync.Mutex{}
)

func invalidate(name string) {
	memoMu.Lock()
	delete(memos, name)
	memoMu.Unlock()
}

func featureLock(name string) *sync.Mutex {
	memoMu.Lock()
	defer memoMu.Unlock()
	l := locks[name]
	if l == nil {
		l = &sync.Mutex{}
		locks[name] = l
	}
	return l
}

// load returns the parsed form of a feed, re-reading only after an update or
// when the cached parse is older than the TTL.
func load(ctx context.Context, name string, parse func([]byte) (any, error)) (any, string) {
	return loadOpt(ctx, name, parse, true)
}

func loadOpt(ctx context.Context, name string, parse func([]byte) (any, error), update bool) (any, string) {
	f := ByName(name)
	if f == nil {
		return nil, "unknown feed " + name
	}
	l := featureLock(name)
	l.Lock()
	defer l.Unlock()
	memoMu.Lock()
	m := memos[name]
	memoMu.Unlock()
	if m != nil && time.Since(m.at) < f.TTL/4+time.Minute {
		return m.v, m.note
	}
	var b []byte
	var note string
	if update {
		b, note = ensure(ctx, f)
	} else if raw, err := os.ReadFile(dataPath(f)); err == nil {
		b = raw
	} else {
		note = f.Name + " not downloaded (traced feeds update)"
	}
	if b == nil {
		if m != nil {
			return m.v, m.note
		}
		return nil, note
	}
	v, err := parse(b)
	if err != nil {
		return nil, fmt.Sprintf("%s: %v", name, err)
	}
	memoMu.Lock()
	memos[name] = &memo{v: v, note: note, at: time.Now()}
	memoMu.Unlock()
	return v, note
}

// NetSet returns the prefix set of a reputation feed (kinetio, spamhaus-drop4/6,
// firehol-l1, et-block, tor-exit) and a note when it is stale/missing.
func NetSet(ctx context.Context, name string) (*Set, string) {
	f := ByName(name)
	if f == nil {
		return nil, "unknown feed " + name
	}
	v, note := load(ctx, name, func(b []byte) (any, error) {
		var e []Entry
		var err error
		switch f.Kind {
		case KindKinetio:
			e, err = ParseKinetio(b)
		case KindDROP:
			e, err = ParseSpamhausDROP(b)
		case KindNetset:
			e, err = ParseNetset(bytes.NewReader(b), f.Type)
		default:
			return nil, fmt.Errorf("%s is not a network list", name)
		}
		if err != nil {
			return nil, err
		}
		return NewSet(e), nil
	})
	s, _ := v.(*Set)
	return s, note
}

// ASNDropList returns Spamhaus ASN-DROP.
func ASNDropList(ctx context.Context) (map[int]ASNDrop, string) {
	v, note := load(ctx, "spamhaus-asndrop", func(b []byte) (any, error) { return ParseASNDrop(b) })
	m, _ := v.(map[int]ASNDrop)
	return m, note
}

type aspop struct {
	m    map[int][]Eyeballs
	date string
}

// EyeballsOf returns the APNIC Labs estimates for an AS (largest economy first)
// and the date of the dataset.
func EyeballsOf(ctx context.Context, asn int) ([]Eyeballs, string, string) {
	v, note := load(ctx, "aspop", func(b []byte) (any, error) {
		m, d, err := ParseASPop(bytes.NewReader(b))
		return &aspop{m, d}, err
	})
	a, _ := v.(*aspop)
	if a == nil {
		return nil, "", note
	}
	return a.m[asn], a.date, note
}

func parseCableDB(b []byte) (any, error) {
	var db CableDB
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, err
	}
	db.index()
	return &db, nil
}

// Cables returns the submarine cable map (refreshing it when stale; the first
// build fetches ~700 cable documents and takes a minute).
func Cables(ctx context.Context) (*CableDB, string) {
	v, note := load(ctx, "cables", parseCableDB)
	db, _ := v.(*CableDB)
	return db, note
}

// CablesLocal returns the cached cable map without any download.
func CablesLocal() *CableDB {
	v, _ := loadOpt(context.Background(), "cables", parseCableDB, false)
	db, _ := v.(*CableDB)
	return db
}

// PDB returns the PeeringDB facility/exchange table.
func PDB(ctx context.Context) (*PeeringDB, string) {
	v, note := load(ctx, "peeringdb", func(b []byte) (any, error) {
		var db PeeringDB
		err := json.Unmarshal(b, &db)
		return &db, err
	})
	db, _ := v.(*PeeringDB)
	return db, note
}

// ---------------- composite builders ----------------

func buildPeeringDB(ctx context.Context, f *Feed) ([]byte, error) {
	base := "https://www.peeringdb.com/api/"
	objs := []string{"fac?depth=0&fields=id,name,city,country,latitude,longitude", "ix?depth=0&fields=id,name,city,country",
		"ixfac?depth=0&fields=ix_id,fac_id",
		"net?depth=0&fields=id,asn,name,aka,website,info_type,info_traffic,info_ratio,info_scope,info_prefixes4,info_prefixes6," +
			"policy_general,policy_url,policy_locations,policy_contracts,irr_as_set,ix_count,fac_count,updated",
		"netixlan?depth=0&fields=net_id,asn,ix_id,speed,ipaddr4,ipaddr6,is_rs_peer,operational",
		"netfac?depth=0&fields=net_id,fac_id,local_asn"}
	// sequential on purpose: anonymous PeeringDB access is rate limited
	res := make([][]byte, len(objs))
	for i, o := range objs {
		b, err := getAuth(ctx, base+o, f.MaxBytes)
		if err != nil {
			if i < 3 {
				// API refused (429 for anonymous clients is common): use the
				// daily full dump CAIDA mirrors from PeeringDB instead
				db, derr := caidaPeeringDB(ctx, f.MaxBytes)
				if derr != nil {
					return nil, fmt.Errorf("%v; CAIDA mirror: %v", err, derr)
				}
				return json.Marshal(db)
			}
			// the network part is optional: keep the places, note the gap
			res[3], res[4], res[5] = nil, nil, nil
			break
		}
		res[i] = b
	}
	if res[3] == nil {
		if old, err := os.ReadFile(dataPath(f)); err == nil {
			var prev PeeringDB
			if json.Unmarshal(old, &prev) == nil && len(prev.Nets) > 0 {
				db, err := BuildPeeringDB(res[0], res[1], res[2], nil, nil, nil)
				if err != nil {
					return nil, err
				}
				db.Nets = prev.Nets
				return json.Marshal(db)
			}
		}
	}
	db, err := BuildPeeringDB(res[0], res[1], res[2], res[3], res[4], res[5])
	if err != nil {
		return nil, err
	}
	return json.Marshal(db)
}

// CAIDAPeeringDBURL is the daily PeeringDB dump archive (%s = yyyy/mm/peeringdb_2_dump_yyyy_mm_dd).
var CAIDAPeeringDBURL = "https://publicdata.caida.org/datasets/peeringdb/%s.json"

// caidaPeeringDB downloads the newest of the last three daily dumps and
// streams out the six tables we need (the dump is ~120 MB).
func caidaPeeringDB(ctx context.Context, limit int64) (*PeeringDB, error) {
	var last error
	for d := 0; d < 3; d++ {
		day := time.Now().UTC().AddDate(0, 0, -d)
		url := fmt.Sprintf(CAIDAPeeringDBURL, day.Format("2006/01/")+"peeringdb_2_dump_"+day.Format("2006_01_02"))
		db, err := streamPeeringDump(ctx, url, limit)
		if err == nil {
			return db, nil
		}
		last = err
		var he *httpErr
		if !errors.As(err, &he) || he.Code != 404 {
			break
		}
	}
	return nil, last
}

func streamPeeringDump(ctx context.Context, url string, limit int64) (*PeeringDB, error) {
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
		return nil, &httpErr{resp.StatusCode, url}
	}
	tables, err := PeeringDumpTables(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	return BuildPeeringDB(tables["fac"], tables["ix"], tables["ixfac"], tables["net"], tables["netixlan"], tables["netfac"])
}

// PeeringDumpTables walks a PeeringDB dump ({"fac":{"data":[…]},"net":…})
// keeping only the tables used by traced.
func PeeringDumpTables(r io.Reader) (map[string][]byte, error) {
	want := map[string]bool{"fac": true, "ix": true, "ixfac": true, "net": true, "netixlan": true, "netfac": true}
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("peeringdb dump: not an object")
	}
	out := map[string][]byte{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("peeringdb dump %s: %w", key, err)
		}
		if want[key] {
			out[key] = raw
		}
	}
	for k := range want {
		if out[k] == nil {
			return nil, fmt.Errorf("peeringdb dump: table %s missing", k)
		}
	}
	return out, nil
}

// getAuth adds the optional PeeringDB API key (PEERINGDB_API_KEY) for higher rate limits.
func getAuth(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	if k := os.Getenv("PEERINGDB_API_KEY"); k != "" && strings.HasPrefix(url, "https://www.peeringdb.com/") {
		req.Header.Set("Authorization", "Api-Key "+k)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &httpErr{resp.StatusCode, url}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: too large", url)
	}
	return b, err
}

// buildCables fetches the cable and landing point GeoJSON plus every cable's
// detail document (length, RFS, owners, landing stations). Details are kept
// per cable in feeds/cable/<id>.json and re-fetched after 30 days, so a weekly
// refresh costs two requests plus the new cables.
func buildCables(ctx context.Context, f *Feed, m *Meta) ([]byte, error) {
	base := strings.TrimRight(f.URL, "/")
	geoMeta := Meta{ETag: m.ETag, LastModified: m.LastModified}
	gb, err := get(ctx, base+"/cable/cable-geo.json", &geoMeta, f.MaxBytes)
	if errors.Is(err, errNotModified) {
		// geometry unchanged; still refresh when detail files went stale
		old, rerr := os.ReadFile(dataPath(f))
		if rerr != nil {
			return nil, rerr
		}
		var db CableDB
		if json.Unmarshal(old, &db) != nil || staleDetails(db.Cables) == 0 {
			return nil, errNotModified
		}
		gb, err = get(ctx, base+"/cable/cable-geo.json", nil, f.MaxBytes)
	}
	if err != nil {
		return nil, err
	}
	m.ETag, m.LastModified = geoMeta.ETag, geoMeta.LastModified
	lb, err := get(ctx, base+"/landing-point/landing-point-geo.json", nil, f.MaxBytes)
	if err != nil {
		return nil, err
	}
	cables, err := ParseCableGeo(gb)
	if err != nil {
		return nil, err
	}
	lps, err := ParseLandingGeo(lb)
	if err != nil {
		return nil, err
	}
	details := fetchDetails(ctx, base, cables)
	got := 0
	for i := range cables {
		if d := details[cables[i].ID]; d != nil {
			cables[i].Apply(d)
			got++
		}
	}
	if got < len(cables)/2 {
		return nil, fmt.Errorf("cable details: only %d of %d fetched", got, len(cables))
	}
	// landing countries from details (more exact than the name suffix)
	cc := map[string]string{}
	for _, d := range details {
		for _, l := range d.LandingPoints {
			if l.Country != "" {
				cc[l.ID] = l.Country
			}
		}
	}
	for i := range lps {
		if c := cc[lps[i].ID]; c != "" {
			lps[i].Country = c
		}
	}
	sort.Slice(cables, func(i, j int) bool { return cables[i].Name < cables[j].Name })
	db := CableDB{Updated: time.Now().UTC().Truncate(time.Second), Source: "https://www.submarinecablemap.com (TeleGeography, CC BY-NC-SA 3.0)",
		Cables: cables, Landing: lps}
	return json.Marshal(db)
}

func detailPath(id string) string {
	return cache.File("feeds", "cable", strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '.' {
			return '_'
		}
		return r
	}, id)+".json")
}

const detailTTL = 30 * 24 * time.Hour

func staleDetails(cs []Cable) int {
	n := 0
	for _, c := range cs {
		if !cache.Fresh(detailPath(c.ID), detailTTL) {
			n++
		}
	}
	return n
}

func fetchDetails(ctx context.Context, base string, cables []Cable) map[string]*CableDetail {
	out := make(map[string]*CableDetail, len(cables))
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < 12; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				p := detailPath(id)
				var b []byte
				if cache.Fresh(p, detailTTL) {
					b, _ = os.ReadFile(p)
				}
				if b == nil {
					nb, err := get(ctx, base+"/cable/"+id+".json", nil, 4<<20)
					if err != nil {
						b, _ = os.ReadFile(p) // fall back to an old copy
					} else {
						b = nb
						_ = writeAtomic(p, nb)
					}
				}
				var d CableDetail
				if b != nil && json.Unmarshal(b, &d) == nil {
					mu.Lock()
					out[id] = &d
					mu.Unlock()
				}
			}
		}()
	}
	for _, c := range cables {
		select {
		case jobs <- c.ID:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// PDBLocal returns the cached PeeringDB table without any download.
func PDBLocal() *PeeringDB {
	v, _ := loadOpt(context.Background(), "peeringdb", func(b []byte) (any, error) {
		var db PeeringDB
		err := json.Unmarshal(b, &db)
		return &db, err
	}, false)
	db, _ := v.(*PeeringDB)
	return db
}
