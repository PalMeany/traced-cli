// Package share publishes finished traces to a public read-only map
// (https://traced.netkitty.dev/t/<id>): the upload client used by the CLI and the
// storage server behind the site.
package share

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/trace"
)

// Limits of an accepted trace.
const (
	MaxBody       = 512 << 10 // bytes of JSON
	maxHops       = 80
	maxResponders = 32
	maxProbes     = 64
	maxRTTs       = 32
)

// Sanitize returns a copy of r that holds only the trace itself: hops,
// responders with their geo/ASN data, the target and its public WHOIS/DNS and
// SNI probe. Local details (history id, interface and tunnel names, notes,
// lookup errors) are dropped. Every loosely typed field is re-decoded into its
// concrete type, so the result marshals to a fixed schema.
func Sanitize(r *trace.Result) (*trace.Result, error) {
	if r == nil {
		return nil, errors.New("empty trace")
	}
	if r.Target == "" {
		return nil, errors.New("target missing")
	}
	if len(r.Hops) == 0 {
		return nil, errors.New("no hops")
	}
	if len(r.Hops) > maxHops {
		return nil, fmt.Errorf("too many hops (%d)", len(r.Hops))
	}
	out := *r
	out.ID = ""
	out.Hops = make([]trace.Hop, len(r.Hops))
	for i, h := range r.Hops {
		if len(h.Responders) > maxResponders {
			return nil, fmt.Errorf("hop %d has too many responders", h.TTL)
		}
		nh := h
		// long MTR sessions: keep the most recent samples only (loss stays in Sent/Received)
		if len(nh.Probes) > maxProbes {
			nh.Probes = nh.Probes[len(nh.Probes)-maxProbes:]
		}
		nh.Responders = make([]trace.Responder, len(h.Responders))
		for j := range h.Responders {
			rs := h.Responders[j]
			if len(rs.RTTs) > maxRTTs {
				rs.RTTs = rs.RTTs[len(rs.RTTs)-maxRTTs:]
			}
			if len(rs.Flows) > maxRTTs {
				rs.Flows = rs.Flows[len(rs.Flows)-maxRTTs:]
			}
			if g := app.InfoOf(&rs); g != nil {
				c := *g
				c.Candidates = nil
				rs.Geo = &c
			} else {
				rs.Geo = nil
			}
			if a := app.ASOf(&rs); a != nil {
				rs.Network = a
			} else {
				rs.Network = nil
			}
			nh.Responders[j] = rs
		}
		out.Hops[i] = nh
	}
	out.Extra = nil
	if ex := app.ExtraOf(r); ex != nil && (ex.Whois != nil || ex.SNI != nil) {
		ne := &app.Extra{SNI: ex.SNI}
		if w := ex.Whois; w != nil {
			cw := *w
			cw.Errors = nil
			ne.Whois = &cw
		}
		out.Extra = ne
	}
	return &out, nil
}

// Decode parses and sanitizes an uploaded trace.
func Decode(b []byte) (*trace.Result, error) {
	var r trace.Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	return Sanitize(&r)
}
