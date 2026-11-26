package feeds

import (
	"bufio"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Entry is one listed network (a single address is a /32 or /128).
type Entry struct {
	Prefix     netip.Prefix `json:"network"`
	Types      []string     `json:"types,omitempty"`      // attack types / categories
	Confidence float64      `json:"confidence,omitempty"` // as published by the feed
	Rung       string       `json:"rung,omitempty"`       // kinetio: address | subnet
	Ref        string       `json:"ref,omitempty"`        // spamhaus SBL id etc.
}

// Single reports whether the entry is one address.
func (e Entry) Single() bool { return e.Prefix.IsSingleIP() }

// Set is a deduplicated prefix list with fast containment queries.
type Set struct {
	entries []Entry // sorted by start address, then shorter prefix first
	byLen   map[int]map[netip.Prefix]int
	lens4   []int // distinct prefix lengths present, v4 (longest first)
	lens6   []int
}

// NewSet normalises (masks), deduplicates and indexes the entries. Duplicate
// networks are merged: attack types are united, the highest confidence kept.
func NewSet(in []Entry) *Set {
	idx := map[netip.Prefix]int{}
	var out []Entry
	for _, e := range in {
		if !e.Prefix.IsValid() {
			continue
		}
		e.Prefix = e.Prefix.Masked()
		if e.Prefix.Addr().Is4In6() {
			a := e.Prefix.Addr().Unmap()
			bits := e.Prefix.Bits() - 96
			if bits < 0 {
				continue
			}
			e.Prefix = netip.PrefixFrom(a, bits).Masked()
		}
		if i, ok := idx[e.Prefix]; ok {
			m := &out[i]
			m.Types = unionStrings(m.Types, e.Types)
			if e.Confidence > m.Confidence {
				m.Confidence = e.Confidence
			}
			if m.Ref == "" {
				m.Ref = e.Ref
			}
			continue
		}
		e.Types = unionStrings(nil, e.Types)
		idx[e.Prefix] = len(out)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Prefix, out[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	s := &Set{entries: out, byLen: map[int]map[netip.Prefix]int{}}
	seen4, seen6 := map[int]bool{}, map[int]bool{}
	for i, e := range out {
		key := e.Prefix.Bits()
		if e.Prefix.Addr().Is6() {
			key += 1000
			if !seen6[e.Prefix.Bits()] {
				seen6[e.Prefix.Bits()] = true
				s.lens6 = append(s.lens6, e.Prefix.Bits())
			}
		} else if !seen4[e.Prefix.Bits()] {
			seen4[e.Prefix.Bits()] = true
			s.lens4 = append(s.lens4, e.Prefix.Bits())
		}
		m := s.byLen[key]
		if m == nil {
			m = map[netip.Prefix]int{}
			s.byLen[key] = m
		}
		m[e.Prefix] = i
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.lens4)))
	sort.Sort(sort.Reverse(sort.IntSlice(s.lens6)))
	return s
}

func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := map[string]bool{}
	var out []string
	for _, x := range append(append([]string{}, a...), b...) {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// Len is the number of distinct networks.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// Entries returns the sorted entries (do not modify).
func (s *Set) Entries() []Entry {
	if s == nil {
		return nil
	}
	return s.entries
}

// Lookup returns every entry that contains addr, most specific first.
func (s *Set) Lookup(addr netip.Addr) []Entry {
	if s == nil || !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()
	lens, off := s.lens4, 0
	if addr.Is6() {
		lens, off = s.lens6, 1000
	}
	var out []Entry
	for _, l := range lens {
		p, err := addr.Prefix(l)
		if err != nil {
			continue
		}
		if i, ok := s.byLen[l+off][p]; ok {
			out = append(out, s.entries[i])
		}
	}
	return out
}

// Contains reports whether addr is listed.
func (s *Set) Contains(addr netip.Addr) bool { return len(s.Lookup(addr)) > 0 }

// Overlap returns the entries inside p (equal or more specific) and the ones
// that cover p (less specific).
func (s *Set) Overlap(p netip.Prefix) (inside, covering []Entry) {
	if s == nil || !p.IsValid() {
		return nil, nil
	}
	p = p.Masked()
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), max(0, p.Bits()-96))
	}
	for _, e := range s.Lookup(p.Addr()) {
		if e.Prefix.Bits() < p.Bits() {
			covering = append(covering, e)
		}
	}
	start := p.Addr()
	i := sort.Search(len(s.entries), func(i int) bool { return s.entries[i].Prefix.Addr().Compare(start) >= 0 })
	for ; i < len(s.entries); i++ {
		e := s.entries[i]
		if e.Prefix.Addr().Is4() != start.Is4() || !p.Contains(e.Prefix.Addr()) {
			break
		}
		if e.Prefix.Bits() >= p.Bits() {
			inside = append(inside, e)
		}
	}
	return inside, covering
}

// ParsePrefix accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::/32" and ranges
// written with a trailing comment ("1.2.3.0/24 ; SBL123").
func ParsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t;#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), true
}

// ParseNetset parses plain IP/CIDR lists (FireHOL .netset/.ipset, Tor bulk
// exit list, Emerging Threats block list): one network per line, "#" and ";"
// comments, blank lines ignored.
func ParseNetset(r io.Reader, typ string) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []Entry
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		p, ok := ParsePrefix(line)
		if !ok {
			continue
		}
		e := Entry{Prefix: p}
		if typ != "" {
			e.Types = []string{typ}
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
