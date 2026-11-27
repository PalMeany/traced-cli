package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/asn"
	"github.com/PalMeany/traced-cli/internal/backbone"
	"github.com/PalMeany/traced-cli/internal/trace"
)

func TestPathIntelVerboseAndShareIP(t *testing.T) {
	prevColor := Color
	Color = false
	defer func() { Color = prevColor }()

	r := &trace.Result{
		Target: "1.1.1.1",
		Extra: &app.Extra{
			ASNs: map[string]*asn.Brief{
				"13335": {ASN: 13335, Name: "CLOUDFLARENET"},
			},
			PrefixBGP: map[string]*asn.PrefixBGP{
				"1.1.1.0/24": {Prefix: "1.1.1.0/24", OriginASN: 13335},
			},
			NAT: trace.AnalyzeNAT("172.19.0.1", "81.90.20.175", []trace.Hop{
				{TTL: 1, Responders: []trace.Responder{{IP: "172.19.0.1"}}},
			}),
			Backbones: []backbone.Hint{
				{ASN: 1299, Provider: "Arelion", TTLs: []int{3, 4}},
			},
		},
	}

	// Default (non-verbose): AS shown; BGP prefixes, NAT and terrestrial backbones hidden.
	var buf bytes.Buffer
	PathIntel(&buf, r, PathIntelOptions{})
	out := buf.String()
	if !strings.Contains(out, "AS on the path") {
		t.Fatalf("default output missing AS section: %s", out)
	}
	for _, hidden := range []string{"BGP prefix upstreams", "NAT", "Terrestrial backbones", "81.90.20.175", "81.90.*.*"} {
		if strings.Contains(out, hidden) {
			t.Errorf("default output should hide %q, got:\n%s", hidden, out)
		}
	}

	// Verbose without --share-ip: sections shown, public IP masked to /16.
	buf.Reset()
	PathIntel(&buf, r, PathIntelOptions{Verbose: true, ShareIP: false})
	out = buf.String()
	for _, want := range []string{"BGP prefix upstreams", "NAT single NAT (1 layer)", "local 172.19.0.1 → public 81.90.*.*", "Terrestrial backbones"} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output missing %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "81.90.20.175") {
		t.Errorf("verbose output without --share-ip leaks full IP:\n%s", out)
	}

	// Verbose with --share-ip: full public IP shown.
	buf.Reset()
	PathIntel(&buf, r, PathIntelOptions{Verbose: true, ShareIP: true})
	out = buf.String()
	if !strings.Contains(out, "local 172.19.0.1 → public 81.90.20.175") {
		t.Errorf("verbose --share-ip missing full IP, got:\n%s", out)
	}
}
