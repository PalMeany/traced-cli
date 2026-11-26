package feeds

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ---------------- Kinetio DTIH ----------------

// kinetioDoc is https://dtih.kinetio.cc/feeds/v1/public?format=json:
//
//	{"feed":"public","entries":[{"network":"1.2.3.4","family":4,"scope":"global",
//	  "rung":"address","attack_types":["scanner"],"confidence":0}, ...]}
type kinetioDoc struct {
	Feed    string `json:"feed"`
	Entries []struct {
		Network     string   `json:"network"`
		Family      int      `json:"family"`
		Scope       string   `json:"scope"`
		Rung        string   `json:"rung"`
		AttackTypes []string `json:"attack_types"`
		Confidence  float64  `json:"confidence"`
	} `json:"entries"`
}

// ParseKinetio parses the Kinetio DTIH JSON feed. Both single addresses and
// CIDR networks are accepted; entries of a non-global scope are kept but
// tagged, malformed ones skipped.
func ParseKinetio(b []byte) ([]Entry, error) {
	var d kinetioDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("kinetio: %w", err)
	}
	if d.Entries == nil {
		return nil, errors.New("kinetio: no entries array")
	}
	out := make([]Entry, 0, len(d.Entries))
	for _, e := range d.Entries {
		p, ok := ParsePrefix(e.Network)
		if !ok {
			continue
		}
		if e.Family == 4 && !p.Addr().Is4() || e.Family == 6 && !p.Addr().Is6() {
			continue
		}
		rung := e.Rung
		if rung == "" {
			rung = "subnet"
			if p.IsSingleIP() {
				rung = "address"
			}
		}
		en := Entry{Prefix: p, Types: e.AttackTypes, Confidence: e.Confidence, Rung: rung}
		if e.Scope != "" && e.Scope != "global" {
			en.Ref = "scope:" + e.Scope
		}
		out = append(out, en)
	}
	return out, nil
}

// ---------------- Spamhaus DROP ----------------

// ParseSpamhausDROP parses the NDJSON DROP lists (drop_v4.json, drop_v6.json):
//
//	{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
//	{"type":"metadata","timestamp":1795613204,...}
//
// The legacy text format ("1.10.16.0/20 ; SBL256894") is accepted as well.
func ParseSpamhausDROP(b []byte) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '{' {
			var r struct {
				CIDR  string `json:"cidr"`
				SBLID string `json:"sblid"`
				Type  string `json:"type"`
			}
			if json.Unmarshal([]byte(line), &r) != nil || r.Type == "metadata" || r.CIDR == "" {
				continue
			}
			if p, ok := ParsePrefix(r.CIDR); ok {
				out = append(out, Entry{Prefix: p, Ref: r.SBLID, Types: []string{"drop"}})
			}
			continue
		}
		ref := ""
		if i := strings.Index(line, ";"); i >= 0 {
			ref = strings.TrimSpace(line[i+1:])
		}
		if p, ok := ParsePrefix(line); ok {
			out = append(out, Entry{Prefix: p, Ref: ref, Types: []string{"drop"}})
		}
	}
	return out, sc.Err()
}

// ASNDrop is one ASN-DROP record.
type ASNDrop struct {
	ASN    int    `json:"asn"`
	RIR    string `json:"rir,omitempty"`
	Domain string `json:"domain,omitempty"`
	CC     string `json:"cc,omitempty"`
	Name   string `json:"asname,omitempty"`
}

// ParseASNDrop parses asndrop.json (NDJSON) or the text list ("AS245 ; US | PRC-AS").
func ParseASNDrop(b []byte) (map[int]ASNDrop, error) {
	out := map[int]ASNDrop{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '{' {
			var r ASNDrop
			var meta struct {
				Type string `json:"type"`
			}
			if json.Unmarshal([]byte(line), &meta) == nil && meta.Type == "metadata" {
				continue
			}
			if json.Unmarshal([]byte(line), &r) == nil && r.ASN > 0 {
				out[r.ASN] = r
			}
			continue
		}
		f := strings.Fields(strings.ReplaceAll(line, ";", " ; "))
		if len(f) == 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(f[0]), "AS"))
		if err != nil || n <= 0 {
			continue
		}
		r := ASNDrop{ASN: n}
		if i := strings.Index(line, ";"); i >= 0 {
			rest := strings.Split(line[i+1:], "|")
			r.CC = strings.TrimSpace(rest[0])
			if len(rest) > 1 {
				r.Name = strings.TrimSpace(rest[1])
			}
		}
		out[n] = r
	}
	return out, sc.Err()
}

// ---------------- APNIC Labs AS population ----------------

// Eyeballs is the APNIC Labs user-population estimate of an AS in one economy.
type Eyeballs struct {
	ASN        int     `json:"asn"`
	CC         string  `json:"cc"`
	Rank       int     `json:"rank"`
	Users      int64   `json:"users"`
	PctCountry float64 `json:"pct_country"`
	PctWorld   float64 `json:"pct_world"`
	Samples    int64   `json:"samples,omitempty"`
}

// ParseASPop parses https://stats.labs.apnic.net/cgi-bin/aspop?c=&f=j into
// ASN → estimates (an AS may serve users in several economies; the list is
// sorted by users, largest first).
func ParseASPop(r io.Reader) (map[int][]Eyeballs, string, error) {
	var d struct {
		Date string `json:"Date"`
		Data []struct {
			Rank    int     `json:"rank"`
			AS      int     `json:"AS"`
			CC      string  `json:"CC"`
			Users   int64   `json:"Users"`
			PctCC   float64 `json:"Percent of CC Pop"`
			PctNet  float64 `json:"Percent of Internet"`
			Samples int64   `json:"Samples"`
		} `json:"Data"`
	}
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, "", fmt.Errorf("aspop: %w", err)
	}
	out := map[int][]Eyeballs{}
	for _, x := range d.Data {
		if x.AS <= 0 {
			continue
		}
		out[x.AS] = append(out[x.AS], Eyeballs{ASN: x.AS, CC: x.CC, Rank: x.Rank, Users: x.Users,
			PctCountry: x.PctCC, PctWorld: x.PctNet, Samples: x.Samples})
	}
	for k := range out {
		v := out[k]
		sort.Slice(v, func(i, j int) bool { return v[i].Users > v[j].Users })
	}
	if len(out) == 0 {
		return nil, "", errors.New("aspop: empty")
	}
	return out, d.Date, nil
}
