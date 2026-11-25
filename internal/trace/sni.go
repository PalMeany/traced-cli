package trace

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// SNI probe outcomes.
const (
	SNIServerHello = "server-hello" // TLS handshake answer from the server
	SNIAlert       = "tls-alert"    // TLS alert from the server (still reached it)
	SNIReset       = "rst"          // TCP RST (often injected by DPI)
	SNIClosed      = "fin"          // connection closed without answer
	SNITimeout     = "timeout"      // silence (drop / blackhole)
	SNITTLExceeded = "ttl-exceeded" // ClientHello died at a router (expected below the server)
	SNIConnectFail = "connect-fail" // TCP handshake itself failed
)

// SNIOptions configure an SNI probe.
type SNIOptions struct {
	Host       string // where to connect (hostname or IP)
	SNI        string // server name sent in ClientHello (default = Host)
	ControlSNI string // harmless SNI for comparison (default example.com)
	Port       int    // default 443
	IPv4, IPv6 bool
	MaxTTL     int
	Timeout    time.Duration
	Interface  string
	NoScan     bool // skip the TTL scan
}

// SNIAttempt is a full-TTL TLS attempt.
type SNIAttempt struct {
	SNI     string  `json:"sni"`
	Outcome string  `json:"outcome"`
	RTT     float64 `json:"rtt_ms"`
	Detail  string  `json:"detail,omitempty"`
}

// SNIStep is one TTL of the ClientHello TTL scan.
type SNIStep struct {
	TTL     int     `json:"ttl"`
	Outcome string  `json:"outcome"`
	Router  string  `json:"router,omitempty"`
	RTT     float64 `json:"rtt_ms,omitempty"`
	Detail  string  `json:"detail,omitempty"`
}

// SNIResult is the report of an SNI probe.
type SNIResult struct {
	Host      string     `json:"host"`
	IP        string     `json:"ip"`
	Port      int        `json:"port"`
	SNI       string     `json:"sni"`
	Target    SNIAttempt `json:"target"`
	Control   SNIAttempt `json:"control"`
	Steps     []SNIStep  `json:"steps,omitempty"`
	ServerTTL int        `json:"server_ttl,omitempty"` // TTL at which the server answered
	DestTTL   int        `json:"dest_ttl,omitempty"`   // hop distance of the destination (TCP SYN trace)
	BlockTTL  int        `json:"block_ttl,omitempty"`  // TTL at which the interference starts
	BlockHop  string     `json:"block_hop,omitempty"`  // last router seen before the interference
	Verdict   string     `json:"verdict"`              // ok | sni-blocked | ip-blocked | unreachable
	Summary   string     `json:"summary"`
}

func (o *SNIOptions) defaults() {
	if o.SNI == "" {
		o.SNI = o.Host
	}
	if o.ControlSNI == "" {
		o.ControlSNI = "example.com"
	}
	if o.Port == 0 {
		o.Port = 443
	}
	if o.MaxTTL <= 0 {
		o.MaxTTL = 30
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
}

// firstReadConn records how the server reacted to the ClientHello.
type firstReadConn struct {
	net.Conn
	once  sync.Once
	first byte
	got   bool
	at    time.Time
}

func (c *firstReadConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.once.Do(func() { c.first, c.got, c.at = b[0], true, time.Now() })
	}
	return n, err
}

// tlsAttempt dials dst, optionally lowers the TTL and sends a ClientHello with sni.
// onPort is called with the local port before the ClientHello is written.
func tlsAttempt(ctx context.Context, dst net.IP, port int, sni string, ttl int, timeout time.Duration,
	ifi *net.Interface, src net.IP, onPort func(int) <-chan struct{}) (outcome string, rtt float64, detail string) {
	v6 := dst.To4() == nil
	d := net.Dialer{Timeout: timeout, Control: sockControl(0, v6, ifi)}
	if src != nil {
		d.LocalAddr = &net.TCPAddr{IP: src}
	}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(dst.String(), fmt.Sprint(port)))
	if err != nil {
		if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
			return SNIReset, 0, "RST on TCP connect"
		}
		return SNIConnectFail, 0, err.Error()
	}
	defer raw.Close()
	tc := raw.(*net.TCPConn)
	if ttl > 0 {
		rc, _ := tc.SyscallConn()
		rc.Control(func(fd uintptr) {
			if v6 {
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
			} else {
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
			}
		})
	}
	var icmpDone <-chan struct{}
	if onPort != nil {
		icmpDone = onPort(tc.LocalAddr().(*net.TCPAddr).Port)
	}
	fc := &firstReadConn{Conn: tc}
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}
	cl := tls.Client(fc, cfg)
	start := time.Now()
	_ = tc.SetDeadline(start.Add(timeout))
	errc := make(chan error, 1)
	go func() { errc <- cl.Handshake() }()
	var herr error
	select {
	case herr = <-errc:
	case <-icmpDone:
		// the ClientHello died at a router; give an injected RST a short chance to arrive
		select {
		case herr = <-errc:
		case <-time.After(300 * time.Millisecond):
			tc.SetDeadline(time.Now())
			<-errc
			return SNITTLExceeded, 0, ""
		}
	case <-ctx.Done():
		tc.SetDeadline(time.Now())
		<-errc
		return SNITimeout, 0, "cancelled"
	}
	if fc.got {
		rtt = msSince(start, fc.at)
		switch fc.first {
		case 0x16:
			if herr != nil {
				return SNIServerHello, rtt, "handshake: " + shortErr(herr)
			}
			st := cl.ConnectionState()
			return SNIServerHello, rtt, fmt.Sprintf("%s %s", tls.VersionName(st.Version), st.NegotiatedProtocol)
		case 0x15:
			return SNIAlert, rtt, shortErr(herr)
		default:
			return SNIServerHello, rtt, fmt.Sprintf("non-TLS answer 0x%02x", fc.first)
		}
	}
	rtt = msSince(start, time.Now())
	switch {
	case herr == nil:
		return SNIServerHello, rtt, ""
	case errors.Is(herr, syscall.ECONNRESET):
		return SNIReset, rtt, "connection reset"
	case errors.Is(herr, io.EOF):
		return SNIClosed, rtt, "closed without answer"
	case errors.Is(herr, os.ErrDeadlineExceeded):
		return SNITimeout, rtt, "no answer"
	}
	var ne net.Error
	if errors.As(herr, &ne) && ne.Timeout() {
		return SNITimeout, rtt, "no answer"
	}
	return SNIClosed, rtt, shortErr(herr)
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}

func reachedServer(outcome string) bool {
	return outcome == SNIServerHello || outcome == SNIAlert
}

// ProbeSNI runs the full SNI analysis: target SNI vs control SNI at full TTL,
// then a TTL scan of the ClientHello to find where the interference happens.
func ProbeSNI(ctx context.Context, o SNIOptions, onStep func(SNIStep)) (*SNIResult, error) {
	o.defaults()
	dst, err := ResolveTarget(o.Host, o.IPv4, o.IPv6)
	if err != nil {
		return nil, err
	}
	res := &SNIResult{Host: o.Host, IP: dst.String(), Port: o.Port, SNI: o.SNI}
	// a session only used as an ICMP listener for TCP time-exceeded messages
	sess, err := NewSession(Options{Target: dst.String(), Protocol: TCP, Port: o.Port, Interface: o.Interface, Probes: 1})
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	// hop distance of the server: a quick single-probe TCP SYN trace
	if tr, err := sess.Trace(ctx, nil); err == nil && tr.Reached && len(tr.Hops) > 0 {
		res.DestTTL = tr.Hops[len(tr.Hops)-1].TTL
	}
	out, rtt, det := tlsAttempt(ctx, dst, o.Port, o.SNI, 0, o.Timeout, sess.ifi, sess.src, nil)
	res.Target = SNIAttempt{SNI: o.SNI, Outcome: out, RTT: rtt, Detail: det}
	out, rtt, det = tlsAttempt(ctx, dst, o.Port, o.ControlSNI, 0, o.Timeout, sess.ifi, sess.src, nil)
	res.Control = SNIAttempt{SNI: o.ControlSNI, Outcome: out, RTT: rtt, Detail: det}

	if !o.NoScan && res.Target.Outcome != SNIConnectFail {
		lastRouter := ""
		silent := 0
		for ttl := 1; ttl <= o.MaxTTL && ctx.Err() == nil; ttl++ {
			var p *pending
			onPort := func(port int) <-chan struct{} {
				p = &pending{key: fmt.Sprintf("t:%d", port), done: make(chan struct{})}
				p.probe.sentAt = time.Now()
				sess.register(p)
				return p.done
			}
			out, rtt, det := tlsAttempt(ctx, dst, o.Port, o.SNI, ttl, o.Timeout, sess.ifi, sess.src, onPort)
			step := SNIStep{TTL: ttl, Outcome: out, RTT: rtt, Detail: det}
			if p != nil {
				sess.drop(p.key)
				select {
				case <-p.done:
					p.mu.Lock()
					step.Router = p.probe.IP
					if out == SNITTLExceeded {
						step.RTT = p.probe.RTT
					}
					p.mu.Unlock()
				default:
				}
			}
			res.Steps = append(res.Steps, step)
			if onStep != nil {
				onStep(step)
			}
			if step.Router != "" && out == SNITTLExceeded {
				lastRouter = step.Router
			}
			if reachedServer(out) {
				res.ServerTTL = ttl
				break
			}
			if out == SNIReset || out == SNIClosed {
				if res.BlockTTL == 0 {
					res.BlockTTL = ttl
					res.BlockHop = lastRouter
				}
				// the same reaction on the next TTLs confirms an on-path middlebox
				silent++
				if silent >= 2 {
					break
				}
				continue
			}
			if out == SNITimeout {
				silent++
				if silent >= 4 {
					break
				}
				continue
			}
			silent = 0
		}
		if res.BlockTTL == 0 && res.ServerTTL == 0 {
			// blackhole: find the first TTL after which only timeouts follow
			for i := len(res.Steps) - 1; i >= 0; i-- {
				if res.Steps[i].Outcome != SNITimeout {
					if i+1 < len(res.Steps) {
						res.BlockTTL = res.Steps[i+1].TTL
						res.BlockHop = res.Steps[i].Router
					}
					break
				}
			}
		}
	}
	classifySNI(res)
	return res, nil
}

func classifySNI(r *SNIResult) {
	t, c := reachedServer(r.Target.Outcome), reachedServer(r.Control.Outcome)
	switch {
	case t:
		r.Verdict = "ok"
		r.Summary = fmt.Sprintf("SNI %s passes: server answered (%s)", r.SNI, r.Target.Outcome)
	case !t && c && r.DestTTL > 0 && r.BlockTTL >= r.DestTTL:
		r.Verdict = "server-rejected"
		r.Summary = fmt.Sprintf("SNI %s gets %s only at the server's own hop (TTL %d) while control SNI %s works — the server (or a box in front of it) refuses this name, no on-path DPI seen", r.SNI, r.Target.Outcome, r.DestTTL, r.Control.SNI)
		return
	case !t && c:
		r.Verdict = "sni-blocked"
		r.Summary = fmt.Sprintf("SNI %s is filtered (%s) while control SNI %s works — DPI on the path", r.SNI, r.Target.Outcome, r.Control.SNI)
	case r.Target.Outcome == SNIConnectFail && r.Control.Outcome == SNIConnectFail:
		r.Verdict = "unreachable"
		r.Summary = "TCP connect fails for any SNI — IP/port blocked or host down"
	default:
		r.Verdict = "ip-blocked"
		r.Summary = fmt.Sprintf("both SNIs fail (%s / %s) — IP-level filtering or server issue", r.Target.Outcome, r.Control.Outcome)
	}
	if r.BlockTTL > 0 && r.Verdict != "ok" {
		where := fmt.Sprintf(" — interference starts at TTL %d", r.BlockTTL)
		if r.BlockHop != "" {
			where += " (right after " + r.BlockHop + ")"
		}
		r.Summary += where
	}
}
