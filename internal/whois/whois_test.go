package whois

import (
	"strings"
	"testing"
)

const rdapDomain = `{
 "objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["client transfer prohibited","active"],
 "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
           {"eventAction":"expiration","eventDate":"2030-08-13T04:00:00Z"},
           {"eventAction":"last changed","eventDate":"2024-08-14T07:01:34Z"}],
 "nameservers":[{"ldhName":"A.IANA-SERVERS.NET"},{"ldhName":"B.IANA-SERVERS.NET"}],
 "secureDNS":{"delegationSigned":true},
 "entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]},
             {"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["org",{},"text","Example Org"]]]}]
}`

func TestParseRDAPDomain(t *testing.T) {
	d, err := ParseRDAPDomainJSON([]byte(rdapDomain))
	if err != nil {
		t.Fatal(err)
	}
	if d.Domain != "example.com" || !strings.HasPrefix(d.Registrar, "RESERVED") || d.Registrant != "Example Org" {
		t.Errorf("names: %+v", d)
	}
	if d.Created != "1995-08-14T04:00:00Z" || d.Expires != "2030-08-13T04:00:00Z" || d.Updated == "" {
		t.Errorf("dates: %+v", d)
	}
	if len(d.Nameservers) != 2 || d.Nameservers[0] != "a.iana-servers.net" || d.DNSSEC != "signed" || len(d.Status) != 2 {
		t.Errorf("ns/status: %+v", d)
	}
}

const rdapIP = `{
 "objectClassName":"ip network","handle":"NET-104-16-0-0-1","name":"CLOUDFLARENET","type":"DIRECT ALLOCATION",
 "startAddress":"104.16.0.0","endAddress":"104.31.255.255","country":"US","port43":"whois.arin.net",
 "cidr0_cidrs":[{"v4prefix":"104.16.0.0","length":12}],
 "remarks":[{"title":"Registration Comments","description":["All Cloudflare abuse reporting can be done via https://www.cloudflare.com/abuse","Geofeed: https://api.cloudflare.com/local-ip-ranges.csv"]}],
 "entities":[{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Cloudflare, Inc."]]],
   "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["email",{},"text","abuse@cloudflare.com"]]]}]}]
}`

func TestParseRDAPIP(t *testing.T) {
	in, err := ParseRDAPIPJSON("104.16.1.1", []byte(rdapIP))
	if err != nil {
		t.Fatal(err)
	}
	if in.NetName != "CLOUDFLARENET" || in.Org != "Cloudflare, Inc." || in.Country != "US" || in.RIR != "ARIN" {
		t.Errorf("fields: %+v", in)
	}
	if len(in.CIDRs) != 1 || in.CIDRs[0] != "104.16.0.0/12" || in.Range != "104.16.0.0 - 104.31.255.255" {
		t.Errorf("range: %+v", in)
	}
	if in.Geofeed != "https://api.cloudflare.com/local-ip-ranges.csv" || in.Abuse != "abuse@cloudflare.com" {
		t.Errorf("geofeed/abuse: %+v", in)
	}
}

const whoisRU = `% TCI Whois Service. Terms of use:
% https://tcinet.ru/documents/whois_ru_rf.pdf

domain:        YANDEX.RU
nserver:       ns1.yandex.ru.
nserver:       ns2.yandex.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           YANDEX, LLC.
taxpayer-id:   7736207543
registrar:     RU-CENTER-RU
admin-contact: https://www.nic.ru/whois
created:       1997-09-23T09:45:07Z
paid-till:     2027-09-30T21:00:00Z
free-date:     2027-11-01
source:        TCI
`

func TestParseWhoisDomain(t *testing.T) {
	d := ParseWhoisDomain("yandex.ru", whoisRU)
	if d.Registrar != "RU-CENTER-RU" || d.Registrant != "YANDEX, LLC." || d.Created != "1997-09-23T09:45:07Z" || d.Expires != "2027-09-30T21:00:00Z" {
		t.Errorf("%+v", d)
	}
	if len(d.Nameservers) != 2 || d.Nameservers[0] != "ns1.yandex.ru" || len(d.Status) != 1 {
		t.Errorf("ns/status %+v", d)
	}
}

const whoisRIPE = `inetnum:        212.188.0.0 - 212.188.63.255
netname:        MTU-NET
country:        RU
org:            ORG-ZM1-RIPE
descr:          MTS PJSC
geofeed:        https://geo.mts.example/feed.csv
abuse-mailbox:  abuse@mts.ru
created:        2002-03-20T12:00:00Z
`

func TestParseWhoisIP(t *testing.T) {
	in := ParseWhoisIP("212.188.6.1", whoisRIPE)
	if in.NetName != "MTU-NET" || in.Country != "RU" || in.Range != "212.188.0.0 - 212.188.63.255" || in.Geofeed != "https://geo.mts.example/feed.csv" || in.Abuse != "abuse@mts.ru" {
		t.Errorf("%+v", in)
	}
}

func TestCymru(t *testing.T) {
	a := ParseCymruOrigin("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11")
	if a == nil || a.ASN != 13335 || a.Prefix != "1.1.1.0/24" || a.Country != "AU" || a.Registry != "apnic" {
		t.Fatalf("%+v", a)
	}
	// multi-origin answers list several ASNs: take the first
	if a := ParseCymruOrigin("174 3356 | 38.0.0.0/8 | US | arin |"); a == nil || a.ASN != 174 {
		t.Fatalf("multi: %+v", a)
	}
	if n := ParseCymruName("13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"); n != "CLOUDFLARENET - Cloudflare, Inc., US" {
		t.Fatalf("name %q", n)
	}
	if ParseCymruOrigin("garbage") != nil {
		t.Fatal("garbage parsed")
	}
}

func TestRegisteredDomain(t *testing.T) {
	for in, want := range map[string]string{"www.cloudflare.com": "cloudflare.com", "a.b.example.co.uk": "example.co.uk",
		"shop.msk.ru": "shop.msk.ru", "example.org.": "example.org", "traced.nuv.cx": "nuv.cx"} {
		if got := RegisteredDomain(in); got != want {
			t.Errorf("%s: %s want %s", in, got, want)
		}
	}
}

func TestReverseName(t *testing.T) {
	if r := reverseName([]byte{1, 2, 3, 4}); r != "4.3.2.1.origin.asn.cymru.com" {
		t.Fatal(r)
	}
}
