package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
)

type ixpEntry struct {
	Prefix  string `json:"prefix"`
	Name    string `json:"name"`
	City    string `json:"city"`
	Country string `json:"country"`
}

// IXP is a matched Internet exchange.
type IXP struct {
	Name    string `json:"name"`
	City    string `json:"city"`
	Country string `json:"country"`
	Prefix  string `json:"prefix,omitempty"`
	Via     string `json:"via,omitempty"` // "prefix" | "rdns"
}

type ixpNet struct {
	n *net.IPNet
	e ixpEntry
}

var (
	ixpOnce sync.Once
	ixpNets []ixpNet
	ixpSrc  = "builtin"
)

func peeringDBFile() string { return cache.File("peeringdb-ixp.json") }

func loadIXP() {
	entries := builtinIXP
	if b, err := os.ReadFile(peeringDBFile()); err == nil {
		var e []ixpEntry
		if json.Unmarshal(b, &e) == nil && len(e) > 100 {
			entries = e
			ixpSrc = "peeringdb-cache"
		}
	}
	for _, e := range entries {
		_, n, err := net.ParseCIDR(e.Prefix)
		if err != nil {
			continue
		}
		ixpNets = append(ixpNets, ixpNet{n, e})
	}
	// longest prefix first
	sort.Slice(ixpNets, func(i, j int) bool {
		a, _ := ixpNets[i].n.Mask.Size()
		b, _ := ixpNets[j].n.Mask.Size()
		return a > b
	})
}

// LookupIXP returns the IXP whose peering LAN contains ip.
func LookupIXP(ip net.IP) *IXP {
	ixpOnce.Do(loadIXP)
	for _, x := range ixpNets {
		if x.n.Contains(ip) {
			return &IXP{Name: x.e.Name, City: x.e.City, Country: x.e.Country, Prefix: x.e.Prefix, Via: "prefix"}
		}
	}
	return nil
}

type ixpHostRule struct {
	substr  string
	name    string
	city    string
	country string
}

var ixpHostRules = []ixpHostRule{
	{"de-cix.net", "DE-CIX", "Frankfurt", "DE"},
	{"decix", "DE-CIX", "Frankfurt", "DE"},
	{"ams-ix.net", "AMS-IX", "Amsterdam", "NL"},
	{"amsix", "AMS-IX", "Amsterdam", "NL"},
	{"msk-ix.ru", "MSK-IX", "Moscow", "RU"},
	{"mskx", "MSK-IX", "Moscow", "RU"},
	{"spb-ix", "SPB-IX", "Saint Petersburg", "RU"},
	{"piter-ix", "PITER-IX", "Saint Petersburg", "RU"},
	{"dataline-ix", "DataLine-IX", "Moscow", "RU"},
	{"w-ix", "W-IX", "Moscow", "RU"},
	{"linx.net", "LINX", "London", "GB"},
	{"lonap.net", "LONAP", "London", "GB"},
	{"franceix.net", "France-IX", "Paris", "FR"},
	{"nl-ix.net", "NL-IX", "Amsterdam", "NL"},
	{"netnod.se", "Netnod", "Stockholm", "SE"},
	{"sthix.net", "STHIX", "Stockholm", "SE"},
	{"swissix.ch", "SwissIX", "Zurich", "CH"},
	{"vix.at", "VIX", "Vienna", "AT"},
	{"bix.hu", "BIX", "Budapest", "HU"},
	{"plix.pl", "PLIX", "Warsaw", "PL"},
	{"thinx.pl", "Thinx IX", "Warsaw", "PL"},
	{"equinix.com", "Equinix IX", "", ""},
	{"ix.br", "IX.br", "Sao Paulo", "BR"},
	{"hkix.net", "HKIX", "Hong Kong", "HK"},
	{"jpix.ad.jp", "JPIX", "Tokyo", "JP"},
	{"bbix.net", "BBIX", "Tokyo", "JP"},
	{"any2ix", "CoreSite Any2", "Los Angeles", "US"},
	{"torix.ca", "TorIX", "Toronto", "CA"},
	{"mix-it.net", "MIX-IT", "Milan", "IT"},
	{"espanix.net", "ESPANIX", "Madrid", "ES"},
	{"ficix.fi", "FICIX", "Helsinki", "FI"},
	{"nix.cz", "NIX.CZ", "Prague", "CZ"},
}

// LookupIXPByHostname detects an Internet Exchange from a router's PTR name
// when its IP is not in the peering LAN prefix table.
func LookupIXPByHostname(host string) *IXP {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil
	}
	for _, r := range ixpHostRules {
		if strings.Contains(h, r.substr) {
			return &IXP{Name: r.name, City: r.city, Country: r.country, Via: "rdns"}
		}
	}
	return nil
}

// IXPSource tells where the IXP table came from and its size.
func IXPSource() (string, int) {
	ixpOnce.Do(loadIXP)
	return ixpSrc, len(ixpNets)
}

// UpdateIXP downloads the full prefix list from the PeeringDB API and caches it.
func UpdateIXP(ctx context.Context) (int, error) {
	cl := &http.Client{Timeout: 90 * time.Second}
	get := func(obj string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.peeringdb.com/api/"+obj+"?depth=0", nil)
		req.Header.Set("User-Agent", UserAgent)
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("peeringdb %s: %s", obj, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(v)
	}
	var ix struct {
		Data []struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			City    string `json:"city"`
			Country string `json:"country"`
		} `json:"data"`
	}
	var lans struct {
		Data []struct {
			ID   int `json:"id"`
			IXID int `json:"ix_id"`
		} `json:"data"`
	}
	var pfx struct {
		Data []struct {
			IXLanID int    `json:"ixlan_id"`
			Prefix  string `json:"prefix"`
		} `json:"data"`
	}
	if err := get("ix", &ix); err != nil {
		return 0, err
	}
	if err := get("ixlan", &lans); err != nil {
		return 0, err
	}
	if err := get("ixpfx", &pfx); err != nil {
		return 0, err
	}
	ixByID := map[int]int{}
	for i, x := range ix.Data {
		ixByID[x.ID] = i
	}
	lanIX := map[int]int{}
	for _, l := range lans.Data {
		lanIX[l.ID] = l.IXID
	}
	var out []ixpEntry
	for _, p := range pfx.Data {
		i, ok := ixByID[lanIX[p.IXLanID]]
		if !ok {
			continue
		}
		x := ix.Data[i]
		city := strings.TrimSpace(strings.Split(strings.Split(x.City, ",")[0], "/")[0])
		out = append(out, ixpEntry{Prefix: p.Prefix, Name: x.Name, City: city, Country: x.Country})
	}
	b, _ := json.Marshal(out)
	if err := os.WriteFile(peeringDBFile(), b, 0o644); err != nil {
		return 0, err
	}
	return len(out), nil
}
