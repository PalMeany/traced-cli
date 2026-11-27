package trace

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// NATHop describes one private or CGNAT hop observed before the public Internet.
type NATHop struct {
	TTL   int    `json:"ttl"`
	IP    string `json:"ip"`
	Scope string `json:"scope"` // rfc1918 | cgnat | link-local | ula
}

// NATResult summarises NAT / CGNAT detection along the outbound path.
type NATResult struct {
	Detected    bool     `json:"detected"`
	Layers      int      `json:"layers"` // 0 = direct, 1 = single, 2 = double, 3 = triple, ...
	Type        string   `json:"type"`   // none | single | double | triple | multi
	CGNAT       bool     `json:"cgnat,omitempty"`
	LocalIP     string   `json:"local_ip,omitempty"`
	PublicIP    string   `json:"public_ip,omitempty"`
	PrivateHops []NATHop `json:"private_hops,omitempty"`
	CGNATHops   []NATHop `json:"cgnat_hops,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

var (
	pubIPMu   sync.Mutex
	pubIPVal  string
	pubIPTime time.Time
)

// DetectNAT inspects the local outbound IP, public IP and trace hops to detect
// single, double, triple+ NAT and Carrier-Grade NAT (RFC 6598 100.64.0.0/10).
func DetectNAT(ctx context.Context, targetIP string, hops []Hop, offline bool) *NATResult {
	localIP := outboundLocalIP(targetIP)
	publicIP := ""
	if !offline {
		publicIP = fetchPublicIP(ctx)
	}
	return AnalyzeNAT(localIP, publicIP, hops)
}

// AnalyzeNAT is the pure NAT/CGNAT classifier (unit-testable without network).
func AnalyzeNAT(localIP, publicIP string, hops []Hop) *NATResult {
	res := &NATResult{
		LocalIP:  strings.TrimSpace(localIP),
		PublicIP: strings.TrimSpace(publicIP),
		Type:     "none",
	}

	loc := net.ParseIP(res.LocalIP)
	pub := net.ParseIP(res.PublicIP)
	locScope := ipScope(loc)

	if locScope == "cgnat" {
		res.CGNAT = true
		res.Evidence = append(res.Evidence, fmt.Sprintf("local address %s is in CGNAT 100.64.0.0/10", res.LocalIP))
	} else if locScope != "" {
		res.Evidence = append(res.Evidence, fmt.Sprintf("local address %s is %s", res.LocalIP, locScope))
	}
	if loc != nil && pub != nil && !loc.Equal(pub) {
		res.Evidence = append(res.Evidence, fmt.Sprintf("local IP %s differs from public IP %s", res.LocalIP, res.PublicIP))
	}

	// Scan hops up to the first public responder to find client/ISP NAT boundaries.
	seenPublic := false
	var prePublic []NATHop
	var postPublic []NATHop
	for _, h := range hops {
		if len(h.Responders) == 0 {
			continue
		}
		ipStr := h.Responders[0].IP
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		sc := ipScope(ip)
		if sc == "" {
			seenPublic = true
			continue
		}
		nh := NATHop{TTL: h.TTL, IP: ipStr, Scope: sc}
		if !seenPublic {
			prePublic = append(prePublic, nh)
		} else {
			postPublic = append(postPublic, nh)
		}
	}

	// Count distinct NAT layers before the first public hop.
	// Heuristic:
	// - Distinct private/CGNAT address blocks (e.g. 192.168.x -> 10.x -> 100.64.x)
	//   or distinct /16 RFC1918 networks indicate separate NAT/router boundaries.
	// - Consecutive hops inside the same /24 subnet are treated as one layer (internal L3).
	layers := 0
	var prevBucket string
	hasCGNAT := res.CGNAT
	for _, nh := range prePublic {
		if nh.Scope == "cgnat" {
			hasCGNAT = true
			res.CGNATHops = append(res.CGNATHops, nh)
		} else {
			res.PrivateHops = append(res.PrivateHops, nh)
		}
		b := natBucket(net.ParseIP(nh.IP), nh.Scope)
		if b != "" && b != prevBucket {
			layers++
			prevBucket = b
			res.Evidence = append(res.Evidence, fmt.Sprintf("hop %d %s (%s)", nh.TTL, nh.IP, nh.Scope))
		}
	}

	// If local IP is private/CGNAT or differs from public IP, there is at least 1 NAT layer
	// even if the router hides ICMP Time Exceeded (* * *).
	if layers == 0 {
		if locScope != "" || (loc != nil && pub != nil && !loc.Equal(pub)) {
			layers = 1
		}
	}
	// If local IP is in one RFC1918 range and the first hop is already in a *different*
	// RFC1918/CGNAT range (e.g. local 192.168.1.5, hop 1 hidden, hop 2 is 100.64.x.x),
	// account for the local router's NAT layer too.
	if locScope != "" && len(prePublic) > 0 {
		locBucket := natBucket(loc, locScope)
		firstBucket := natBucket(net.ParseIP(prePublic[0].IP), prePublic[0].Scope)
		if locBucket != "" && firstBucket != "" && locBucket != firstBucket && prePublic[0].TTL > 1 {
			layers++
			res.Evidence = append(res.Evidence, fmt.Sprintf("local subnet (%s) differs from hop %d (%s)", locBucket, prePublic[0].TTL, firstBucket))
		}
	}

	if len(postPublic) > 0 {
		res.Evidence = append(res.Evidence, fmt.Sprintf("%d private/carrier hop(s) after first public hop (ignored for client NAT)", len(postPublic)))
	}

	res.CGNAT = hasCGNAT
	res.Layers = layers
	res.Detected = layers > 0
	switch {
	case layers <= 0:
		res.Type = "none"
	case layers == 1:
		res.Type = "single"
	case layers == 2:
		res.Type = "double"
	case layers == 3:
		res.Type = "triple"
	default:
		res.Type = "multi"
	}
	return res
}

func ipScope(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return "cgnat"
		}
		if v4[0] == 10 || (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) || (v4[0] == 192 && v4[1] == 168) {
			return "rfc1918"
		}
		if v4[0] == 169 && v4[1] == 254 {
			return "link-local"
		}
		return ""
	}
	if ip.IsLinkLocalUnicast() {
		return "link-local"
	}
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return "ula"
	}
	return ""
}

func natBucket(ip net.IP, scope string) string {
	if ip == nil || scope == "" {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		switch scope {
		case "cgnat":
			return "cgnat:100.64/10"
		case "rfc1918":
			switch {
			case v4[0] == 192 && v4[1] == 168:
				return fmt.Sprintf("192.168.%d/24", v4[2])
			case v4[0] == 10:
				return fmt.Sprintf("10.%d/16", v4[1])
			case v4[0] == 172:
				return fmt.Sprintf("172.%d/16", v4[1])
			}
		default:
			return scope
		}
	}
	return scope
}

func outboundLocalIP(targetIP string) string {
	if targetIP == "" {
		targetIP = "1.1.1.1"
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort(targetIP, "53"), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
		return ua.IP.String()
	}
	return ""
}

func fetchPublicIP(ctx context.Context) string {
	pubIPMu.Lock()
	if pubIPVal != "" && time.Since(pubIPTime) < 2*time.Minute {
		v := pubIPVal
		pubIPMu.Unlock()
		return v
	}
	pubIPMu.Unlock()

	cl := &http.Client{Timeout: 2500 * time.Millisecond}
	endpoints := []string{
		"https://1.1.1.1/cdn-cgi/trace",
		"https://api.ipify.org",
	}
	for _, u := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "traced-cli")
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		ip := parsePublicIPBody(string(b))
		if ip != "" {
			pubIPMu.Lock()
			pubIPVal, pubIPTime = ip, time.Now()
			pubIPMu.Unlock()
			return ip
		}
	}
	return ""
}

func parsePublicIPBody(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "ip=") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			if ip := net.ParseIP(v); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

// MaskIP hides the host part of an IP address: IPv4 is masked to /16
// (e.g. 81.90.20.175 -> 81.90.*.*), IPv6 to /32 (e.g. 2001:db8::*).
func MaskIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.*.*", v4[0], v4[1])
	}
	if len(ip) == net.IPv6len {
		return fmt.Sprintf("%x:%x::*", uint16(ip[0])<<8|uint16(ip[1]), uint16(ip[2])<<8|uint16(ip[3]))
	}
	return s
}

// RedactNAT returns a copy of n with PublicIP (and any public IP mention in
// Evidence) masked to /16 (IPv4) or /32 (IPv6).
func RedactNAT(n *NATResult) *NATResult {
	if n == nil {
		return nil
	}
	cp := *n
	origPub := strings.TrimSpace(n.PublicIP)
	maskedPub := MaskIP(origPub)
	cp.PublicIP = maskedPub
	if len(n.Evidence) > 0 {
		ev := make([]string, len(n.Evidence))
		for i, line := range n.Evidence {
			if origPub != "" && maskedPub != origPub {
				line = strings.ReplaceAll(line, origPub, maskedPub)
			}
			const marker = "differs from public IP "
			if idx := strings.Index(line, marker); idx >= 0 {
				rest := line[idx+len(marker):]
				end := strings.IndexAny(rest, " ,;)")
				tok := rest
				suffix := ""
				if end >= 0 {
					tok = rest[:end]
					suffix = rest[end:]
				}
				if ip := net.ParseIP(tok); ip != nil {
					line = line[:idx+len(marker)] + MaskIP(tok) + suffix
				}
			}
			ev[i] = line
		}
		cp.Evidence = ev
	}
	return &cp
}
