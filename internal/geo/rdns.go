package geo

import (
	"regexp"
	"strings"
)

// Backbone describes a recognised carrier from its PTR domain.
type Backbone struct {
	Name string `json:"name"`
	ASN  int    `json:"asn,omitempty"`
}

var backbones = []struct {
	suffix string
	b      Backbone
}{
	{"cogentco.com", Backbone{"Cogent", 174}},
	{"twelve99.net", Backbone{"Arelion (Telia)", 1299}},
	{"telia.net", Backbone{"Arelion (Telia)", 1299}},
	{"ntt.net", Backbone{"NTT", 2914}},
	{"level3.net", Backbone{"Lumen (Level3)", 3356}},
	{"lumen.tech", Backbone{"Lumen", 3356}},
	{"centurylink.net", Backbone{"Lumen", 209}},
	{"gtt.net", Backbone{"GTT", 3257}},
	{"he.net", Backbone{"Hurricane Electric", 6939}},
	{"zayo.com", Backbone{"Zayo", 6461}},
	{"as6453.net", Backbone{"Tata Communications", 6453}},
	{"tatacommunications.com", Backbone{"Tata Communications", 6453}},
	{"seabone.net", Backbone{"Telecom Italia Sparkle", 6762}},
	{"opentransit.net", Backbone{"Orange (OpenTransit)", 5511}},
	{"telekom.de", Backbone{"Deutsche Telekom", 3320}},
	{"dtag.de", Backbone{"Deutsche Telekom", 3320}},
	{"vodafone.com", Backbone{"Vodafone", 1273}},
	{"pccwbtn.net", Backbone{"PCCW Global", 3491}},
	{"telstraglobal.net", Backbone{"Telstra", 4637}},
	{"retn.net", Backbone{"RETN", 9002}},
	{"rostelecom.ru", Backbone{"Rostelecom", 12389}},
	{"rt.ru", Backbone{"Rostelecom", 12389}},
	{"rt-comm.ru", Backbone{"Rostelecom", 12389}},
	{"transtelecom.net", Backbone{"TTK", 20485}},
	{"ttk.ru", Backbone{"TTK", 20485}},
	{"mts-internet.net", Backbone{"MTS", 8359}},
	{"megafon.ru", Backbone{"MegaFon", 31133}},
	{"corbina.net", Backbone{"Beeline", 3216}},
	{"beeline.ru", Backbone{"Beeline", 3216}},
	{"selectel.ru", Backbone{"Selectel", 49505}},
	{"selectel.org", Backbone{"Selectel", 49505}},
	{"yndx.net", Backbone{"Yandex", 13238}},
	{"yandex.net", Backbone{"Yandex", 13238}},
	{"1e100.net", Backbone{"Google", 15169}},
	{"google.com", Backbone{"Google", 15169}},
	{"amazonaws.com", Backbone{"Amazon AWS", 16509}},
	{"aws.com", Backbone{"Amazon AWS", 16509}},
	{"cloudflare.com", Backbone{"Cloudflare", 13335}},
	{"akamaitechnologies.com", Backbone{"Akamai", 20940}},
	{"akamai.net", Backbone{"Akamai", 20940}},
	{"fastly.net", Backbone{"Fastly", 54113}},
	{"msn.net", Backbone{"Microsoft", 8075}},
	{"microsoft.com", Backbone{"Microsoft", 8075}},
	{"hetzner.com", Backbone{"Hetzner", 24940}},
	{"your-server.de", Backbone{"Hetzner", 24940}},
	{"ovh.net", Backbone{"OVHcloud", 16276}},
	{"leaseweb.net", Backbone{"Leaseweb", 60781}},
	{"core-backbone.com", Backbone{"Core-Backbone", 33891}},
	{"init7.net", Backbone{"Init7", 13030}},
	{"liberty-global.net", Backbone{"Liberty Global", 6830}},
	{"edgeuno.com", Backbone{"EdgeUno", 7195}},
	{"digitalocean.com", Backbone{"DigitalOcean", 14061}},
	{"linode.com", Backbone{"Akamai Linode", 63949}},
	{"g-core.net", Backbone{"G-Core Labs", 199524}},
	{"gcore.lu", Backbone{"G-Core Labs", 199524}},
	{"datahouse.ru", Backbone{"DataHouse", 0}},
	{"dataline.ru", Backbone{"DataLine", 0}},
	{"ix.ru", Backbone{"MSK-IX", 8631}},
	{"msk-ix.ru", Backbone{"MSK-IX", 8631}},
	{"de-cix.net", Backbone{"DE-CIX", 6695}},
	{"ams-ix.net", Backbone{"AMS-IX", 1200}},
	{"linx.net", Backbone{"LINX", 5459}},
}

// cloud region hints (provider region names inside PTR records)
var regionHints = []struct {
	re   *regexp.Regexp
	code string
}{
	{regexp.MustCompile(`eu-central-1|europe-west3`), "fra"},
	{regexp.MustCompile(`eu-west-1|europe-west1`), "dub"},
	{regexp.MustCompile(`eu-west-2|europe-west2`), "lon"},
	{regexp.MustCompile(`eu-west-3|europe-west9`), "par"},
	{regexp.MustCompile(`eu-north-1`), "sto"},
	{regexp.MustCompile(`eu-south-1|europe-west8`), "mil"},
	{regexp.MustCompile(`europe-west4`), "ams"},
	{regexp.MustCompile(`europe-north1`), "hel"},
	{regexp.MustCompile(`us-east-1|us-east4`), "iad"},
	{regexp.MustCompile(`us-east-2`), "cmh"},
	{regexp.MustCompile(`us-west-1`), "sfo"},
	{regexp.MustCompile(`us-west-2`), "pdx"},
	{regexp.MustCompile(`ap-southeast-1|asia-southeast1`), "sin"},
	{regexp.MustCompile(`ap-northeast-1|asia-northeast1`), "nrt"},
	{regexp.MustCompile(`ap-east-1|asia-east2`), "hkg"},
	{regexp.MustCompile(`ap-south-1|asia-south1`), "bom"},
	{regexp.MustCompile(`ap-southeast-2|australia-southeast1`), "syd"},
	{regexp.MustCompile(`sa-east-1|southamerica-east1`), "gru"},
	{regexp.MustCompile(`ca-central-1`), "yul"},
	{regexp.MustCompile(`me-central-1`), "dxb"},
}

// tokens that look like codes but are network jargon in PTR names
var rdnsStop = map[string]bool{
	"acc": true, "sub": true, "tun": true, "los": true, "bah": true, "doh": true, "den": true,
	"got": true, "ord": true, "was": true, "bud": true, "dub": true, "res": true, "ren": true,
	"kem": true, "yar": true, "sin": true, "ufa": true, "mad": true, "osl": true, "ist": true,
	"can": true, "man": true, "per": true, "for": true, "nice": true, "rio": true, "sao": true,
}

// tokens that are never locations in PTR names (interface / role names)
var rdnsNever = map[string]bool{"tun": true, "acc": true, "sub": true, "gen": true, "los": true}

// RDNSMatch is the result of parsing a PTR name.
type RDNSMatch struct {
	City       *City
	Token      string
	Confidence float64
	Backbone   *Backbone
}

var splitRe = regexp.MustCompile(`[^a-z0-9]+`)
var alphaPrefix = regexp.MustCompile(`^([a-z]{3,})\d`)

// ParseHostname extracts a location hint and the carrier from a PTR record.
func ParseHostname(host string) *RDNSMatch {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return nil
	}
	m := &RDNSMatch{}
	domainLabels := 2
	for _, bb := range backbones {
		if h == bb.suffix || strings.HasSuffix(h, "."+bb.suffix) {
			b := bb.b
			m.Backbone = &b
			domainLabels = strings.Count(bb.suffix, ".") + 1
			break
		}
	}
	labels := strings.Split(h, ".")
	if m.Backbone == nil && len(labels) >= 3 {
		// second-level public suffixes like co.uk, com.ru, net.br
		sl := labels[len(labels)-2]
		if sl == "co" || sl == "com" || sl == "net" || sl == "org" || sl == "ne" || sl == "or" {
			domainLabels = 3
		}
	}
	if len(labels) <= domainLabels {
		// only the registered domain itself: no location info expected
		// (still allow region hints)
		labels = nil
	} else {
		labels = labels[:len(labels)-domainLabels]
	}
	for _, rh := range regionHints {
		if rh.re.MatchString(h) {
			if c := cityByCode[rh.code]; c != nil {
				m.City, m.Token, m.Confidence = c, rh.re.String(), 0.8
				return m
			}
		}
	}
	best := 0.0
	consider := func(c *City, tok string, conf float64) {
		if c != nil && conf > best {
			best = conf
			m.City, m.Token, m.Confidence = c, tok, conf
		}
	}
	for _, lab := range labels {
		toks := splitRe.Split(lab, -1)
		// also try the whole label without separators (e.g. "new-york" -> "newyork")
		if strings.ContainsAny(lab, "-_") {
			toks = append(toks, strings.Map(func(r rune) rune {
				if r == '-' || r == '_' {
					return -1
				}
				return r
			}, lab))
		}
		for _, t := range toks {
			if t == "" {
				continue
			}
			base := strings.TrimRight(t, "0123456789")
			hasDigits := base != t
			if rdnsNever[base] {
				continue
			}
			// alias exactly as written (m9, msk-ix style tokens)
			if c, ok := aliasIndex[t]; ok && len(t) >= 2 && (!rdnsStop[t]) {
				conf := 0.65
				if len(t) >= 5 {
					conf = 0.8
				}
				consider(c, t, conf)
			}
			if base == "" {
				continue
			}
			if c, ok := aliasIndex[base]; ok && hasDigits && len(base) >= 3 && !rdnsStop[base] {
				conf := 0.75
				if len(base) >= 5 {
					conf = 0.8
				}
				consider(c, t, conf)
			}
			if c, ok := weakAliases[base]; ok && hasDigits && len(base) >= 3 {
				consider(c, t, 0.45)
			}
			if c, ok := aliasIndex[base]; ok && hasDigits && rdnsStop[base] {
				consider(c, t, 0.5)
			}
			// google style "fra16s52"
			if mm := alphaPrefix.FindStringSubmatch(t); mm != nil && mm[1] != base {
				if c, ok := aliasIndex[mm[1]]; ok && !rdnsStop[mm[1]] && !rdnsNever[mm[1]] {
					consider(c, t, 0.7)
				}
			}
			// NTT CLLI-like "frnkge13" -> "frnkge"/"frnk"
			if len(base) == 6 {
				if c, ok := aliasIndex[base[:4]]; ok {
					consider(c, t, 0.7)
				}
			}
		}
	}
	if m.City == nil && m.Backbone == nil {
		return nil
	}
	return m
}
