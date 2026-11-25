// Package trace implements the traceroute engine: ICMP / TCP / UDP probes over
// IPv4 and IPv6, multi-probe ECMP discovery, MPLS label parsing (RFC 4950) and
// TLS SNI probing.
package trace

import (
	"net"
	"sort"
	"time"
)

// Protocol of the probes.
type Protocol string

const (
	ICMP Protocol = "icmp"
	TCP  Protocol = "tcp"
	UDP  Protocol = "udp"
)

// Options configure a trace run.
type Options struct {
	Target    string        // hostname or IP literal
	Protocol  Protocol      // icmp (default), tcp, udp
	Port      int           // destination port (tcp default 443, udp default 33434)
	IPv6      bool          // force IPv6
	IPv4      bool          // force IPv4
	FirstTTL  int           // default 1
	MaxTTL    int           // default 30
	Probes    int           // probes per TTL (default 3)
	Timeout   time.Duration // per-probe timeout (default 2s)
	Interval  time.Duration // pause between consecutive probe sends (default 8ms)
	Paris     bool          // keep the flow identifier constant (no ECMP spreading)
	PacketLen int           // payload size for ICMP/UDP probes
	Interface string        // bind probes to this interface (bypass VPN/TUN routing)
}

func (o *Options) defaults() {
	if o.Protocol == "" {
		o.Protocol = ICMP
	}
	if o.Port == 0 {
		switch o.Protocol {
		case TCP:
			o.Port = 443
		case UDP:
			o.Port = 33434
		}
	}
	if o.FirstTTL <= 0 {
		o.FirstTTL = 1
	}
	if o.MaxTTL <= 0 {
		o.MaxTTL = 30
	}
	if o.MaxTTL > 64 {
		o.MaxTTL = 64
	}
	if o.Probes <= 0 {
		o.Probes = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Interval <= 0 {
		o.Interval = 12 * time.Millisecond
	}
	if o.PacketLen <= 0 {
		o.PacketLen = 32
	}
}

// MPLSLabel is one entry of an MPLS label stack (RFC 4950).
type MPLSLabel struct {
	Label int  `json:"label"`
	TC    int  `json:"tc"`
	S     bool `json:"s"`
	TTL   int  `json:"ttl"`
}

// Reply kinds.
const (
	KindTimeExceeded = "ttl"     // ICMP time exceeded from a router
	KindEchoReply    = "echo"    // ICMP echo reply from destination
	KindUnreachable  = "unreach" // ICMP destination unreachable
	KindTCPSynAck    = "synack"  // TCP connect succeeded (port open)
	KindTCPRst       = "rst"     // TCP RST (port closed but host reached)
	KindUDPReply     = "udp"     // UDP data from destination
)

// Probe is the result of one probe.
type Probe struct {
	TTL    int         `json:"ttl"`
	Index  int         `json:"index"` // flow index (0..Probes-1)
	IP     string      `json:"ip,omitempty"`
	RTT    float64     `json:"rtt_ms,omitempty"` // milliseconds
	Kind   string      `json:"kind,omitempty"`
	Code   int         `json:"code,omitempty"`
	MPLS   []MPLSLabel `json:"mpls,omitempty"`
	Lost   bool        `json:"lost,omitempty"`
	Final  bool        `json:"final,omitempty"` // reply comes from the destination
	sentAt time.Time
}

// Responder aggregates probes coming from one IP on a hop.
type Responder struct {
	IP      string      `json:"ip"`
	Host    string      `json:"host,omitempty"`
	RTTs    []float64   `json:"rtts"`
	Flows   []int       `json:"flows"`
	MPLS    []MPLSLabel `json:"mpls,omitempty"`
	Final   bool        `json:"final,omitempty"`
	Kind    string      `json:"kind,omitempty"`
	Geo     any         `json:"geo,omitempty"` // filled by the geo layer (*geo.Info)
	Network any         `json:"net,omitempty"` // ASN info (*geo.ASInfo)
}

// Hop is the aggregated result for one TTL.
type Hop struct {
	TTL        int         `json:"ttl"`
	Probes     []Probe     `json:"probes"`
	Responders []Responder `json:"responders"`
	Sent       int         `json:"sent"`
	Received   int         `json:"received"`
	Final      bool        `json:"final,omitempty"`
}

// Loss returns the loss ratio (0..1).
func (h *Hop) Loss() float64 {
	if h.Sent == 0 {
		return 0
	}
	return 1 - float64(h.Received)/float64(h.Sent)
}

// ECMP reports whether more than one router answered on this TTL.
func (h *Hop) ECMP() bool { return len(h.Responders) > 1 }

// Primary returns the responder with the most replies (or nil).
func (h *Hop) Primary() *Responder {
	if len(h.Responders) == 0 {
		return nil
	}
	return &h.Responders[0]
}

// MinRTT over all replies of the hop (0 when nothing answered).
func (h *Hop) MinRTT() float64 {
	m := 0.0
	for _, p := range h.Probes {
		if p.Lost || p.RTT <= 0 {
			continue
		}
		if m == 0 || p.RTT < m {
			m = p.RTT
		}
	}
	return m
}

// AvgRTT over all replies of the hop.
func (h *Hop) AvgRTT() float64 {
	s, n := 0.0, 0
	for _, p := range h.Probes {
		if !p.Lost && p.RTT > 0 {
			s += p.RTT
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return s / float64(n)
}

// Aggregate builds the responder list from raw probes.
func Aggregate(ttl int, probes []Probe) Hop {
	h := Hop{TTL: ttl, Probes: probes, Sent: len(probes)}
	idx := map[string]int{}
	for _, p := range probes {
		if p.Lost || p.IP == "" {
			continue
		}
		h.Received++
		i, ok := idx[p.IP]
		if !ok {
			i = len(h.Responders)
			idx[p.IP] = i
			h.Responders = append(h.Responders, Responder{IP: p.IP, Kind: p.Kind})
		}
		r := &h.Responders[i]
		r.RTTs = append(r.RTTs, p.RTT)
		r.Flows = append(r.Flows, p.Index)
		if len(p.MPLS) > 0 && len(r.MPLS) == 0 {
			r.MPLS = p.MPLS
		}
		if p.Final {
			r.Final = true
			h.Final = true
		}
	}
	sort.SliceStable(h.Responders, func(a, b int) bool {
		return len(h.Responders[a].RTTs) > len(h.Responders[b].RTTs)
	})
	return h
}

// Result is a complete trace.
type Result struct {
	ID        string    `json:"id,omitempty"`
	Target    string    `json:"target"`
	TargetIP  string    `json:"target_ip"`
	Protocol  Protocol  `json:"protocol"`
	Port      int       `json:"port,omitempty"`
	IPv6      bool      `json:"ipv6,omitempty"`
	Privilege string    `json:"privilege,omitempty"` // raw | dgram
	Started   time.Time `json:"started"`
	Duration  float64   `json:"duration_ms"`
	Reached   bool      `json:"reached"`
	Hops      []Hop     `json:"hops"`
	Extra     any       `json:"extra,omitempty"` // whois/dns/sni blocks attached by the CLI
}

// Event is streamed while the trace runs.
type Event struct {
	Type   string   `json:"type"` // start | hop | whois | sni-step | sni | note | done | error
	Hop    *Hop     `json:"hop,omitempty"`
	Result *Result  `json:"result,omitempty"`
	Step   *SNIStep `json:"step,omitempty"`
	Data   any      `json:"data,omitempty"`
	Note   string   `json:"note,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// ResolveTarget turns a hostname into an IP of the wanted family.
func ResolveTarget(target string, v4, v6 bool) (net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		is4 := ip.To4() != nil
		if v6 && !is4 {
			return ip, nil
		}
		if !v6 && is4 {
			return ip, nil
		}
	}
	if !v4 && !v6 && len(ips) > 0 {
		return ips[0], nil
	}
	return nil, &net.DNSError{Err: "no address of requested family", Name: target}
}
