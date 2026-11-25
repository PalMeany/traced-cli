package trace

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// pending is an in-flight probe.
type pending struct {
	probe   Probe
	key     string
	done    chan struct{}
	sent    chan struct{}
	skipped bool
	once    sync.Once
	mu      sync.Mutex
}

func (p *pending) complete(fill func(*Probe)) {
	p.once.Do(func() {
		p.mu.Lock()
		fill(&p.probe)
		p.mu.Unlock()
		close(p.done)
	})
}

// Session holds the sockets of a trace target; it can run several traces
// (used by the live MTR mode).
type Session struct {
	Opts      Options
	Dst       net.IP
	V6        bool
	Privilege string // raw | dgram

	conn    *icmpConn
	ifi     *net.Interface
	src     net.IP
	writeMu sync.Mutex
	icmpID  int
	seq     uint32
	port    uint32

	mu      sync.Mutex
	pending map[string]*pending

	udpConns []*net.UDPConn
	closed   chan struct{}
	finalTTL atomic.Int32
}

// NewSession resolves the target and opens the ICMP listener.
func NewSession(opts Options) (*Session, error) {
	opts.defaults()
	dst, err := ResolveTarget(opts.Target, opts.IPv4, opts.IPv6)
	if err != nil {
		return nil, err
	}
	s := &Session{
		Opts:    opts,
		Dst:     dst,
		V6:      dst.To4() == nil,
		icmpID:  (os.Getpid() ^ rand.Intn(0xffff)) & 0xffff,
		pending: map[string]*pending{},
		closed:  make(chan struct{}),
	}
	s.seq = uint32(rand.Intn(20000))
	s.port = uint32(33000 + rand.Intn(20000))
	if err := s.openICMP(); err != nil {
		return nil, err
	}
	if opts.Protocol == UDP {
		for i := 0; i < opts.Probes; i++ {
			c, err := s.listenUDP()
			if err != nil {
				s.Close()
				return nil, err
			}
			s.udpConns = append(s.udpConns, c)
		}
	}
	go s.receive()
	return s, nil
}

func (s *Session) openICMP() error {
	if s.Opts.Interface != "" {
		ifi, err := net.InterfaceByName(s.Opts.Interface)
		if err != nil {
			return fmt.Errorf("interface %q: %v", s.Opts.Interface, err)
		}
		s.ifi = ifi
		s.src = interfaceAddr(ifi, s.V6)
		if s.src == nil {
			return fmt.Errorf("interface %q has no usable address of this family", ifi.Name)
		}
	}
	var lastErr error
	modes := []bool{false}
	if os.Geteuid() == 0 {
		modes = []bool{true, false}
	}
	for _, raw := range modes {
		c, err := listenICMP(s.V6, raw, s.ifi, s.src)
		if err != nil {
			lastErr = err
			continue
		}
		s.conn = c
		s.Privilege = map[bool]string{true: "raw", false: "dgram"}[raw]
		return nil
	}
	hint := ""
	if runtime.GOOS == "linux" {
		hint = " (run with sudo, setcap cap_net_raw+ep, or allow ping sockets via sysctl net.ipv4.ping_group_range)"
	}
	return fmt.Errorf("cannot open ICMP socket: %v%s", lastErr, hint)
}

func (s *Session) listenUDP() (*net.UDPConn, error) {
	network := "udp4"
	if s.V6 {
		network = "udp6"
	}
	lc := net.ListenConfig{Control: sockControl(0, s.V6, s.ifi)}
	for i := 0; i < 50; i++ {
		p := int(atomic.AddUint32(&s.port, 1))%30000 + 33000
		c, err := lc.ListenPacket(context.Background(), network, net.JoinHostPort(ipOrEmpty(s.src), fmt.Sprint(p)))
		if err == nil {
			return c.(*net.UDPConn), nil
		}
	}
	return nil, errors.New("cannot bind UDP source port")
}

// Close releases all sockets.
func (s *Session) Close() {
	select {
	case <-s.closed:
		return
	default:
	}
	close(s.closed)
	if s.conn != nil {
		s.conn.Close()
	}
	for _, c := range s.udpConns {
		c.Close()
	}
}

func (s *Session) register(p *pending) {
	s.mu.Lock()
	s.pending[p.key] = p
	s.mu.Unlock()
}

func (s *Session) take(key string) *pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[key]
	if p != nil {
		delete(s.pending, key)
	}
	return p
}

func (s *Session) drop(key string) {
	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
}

// receive reads ICMP messages and matches them with pending probes.
func (s *Session) receive() {
	buf := make([]byte, 1500)
	for {
		pkt, peer, err := s.conn.ReadFrom(buf)
		now := time.Now()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		m, ok := parseICMP(pkt, s.V6)
		if debug {
			fmt.Fprintf(os.Stderr, "[recv] from=%v len=%d type=%d code=%d ok=%v inner=%d mpls=%v\n", peer, len(pkt), m.typeOr(-1), m.codeOr(-1), ok, len(m.innerOr()), m.mplsOr())
		}
		if !ok {
			continue
		}
		from := addrIP(peer)
		var key, kind string
		switch {
		case (!s.V6 && m.Type == icmp4EchoReply) || (s.V6 && m.Type == icmp6EchoReply):
			if s.Opts.Protocol != ICMP {
				continue
			}
			key = fmt.Sprintf("i:%d", m.Seq)
			kind = KindEchoReply
		case m.Inner != nil:
			in, ok := parseInner(m.Inner, s.V6)
			if !ok || !in.Dst.Equal(s.Dst) {
				continue
			}
			switch in.Proto {
			case 1, 58:
				key = fmt.Sprintf("i:%d", in.Seq)
			case 6:
				key = fmt.Sprintf("t:%d", in.SrcPort)
			case 17:
				key = fmt.Sprintf("u:%d:%d", in.SrcPort, udpLenFromInner(m.Inner, s.V6))
			default:
				continue
			}
			if (!s.V6 && m.Type == icmp4TimeExceeded) || (s.V6 && m.Type == icmp6TimeExceeded) {
				kind = KindTimeExceeded
			} else {
				kind = KindUnreachable
			}
		default:
			continue
		}
		p := s.take(key)
		if p == nil {
			continue
		}
		mpls := m.MPLS
		code := m.Code
		ip := from.String()
		final := from.Equal(s.Dst) || kind == KindEchoReply
		p.complete(func(pr *Probe) {
			pr.IP = ip
			pr.RTT = msSince(pr.sentAt, now)
			if s.Opts.Protocol == TCP && pr.RTT >= 1000 && pr.RTT < 2000 {
				// the reply matched the kernel's SYN retransmission (initial RTO 1 s)
				pr.RTT -= 1000
			}
			pr.Kind = kind
			pr.Code = code
			pr.MPLS = mpls
			pr.Final = final || kind == KindUnreachable && from.Equal(s.Dst)
		})
	}
}

func udpLenFromInner(b []byte, v6 bool) int {
	off := 40
	if !v6 {
		if len(b) < 20 {
			return 0
		}
		off = int(b[0]&0x0f) * 4
	}
	if len(b) < off+6 {
		return 0
	}
	return int(b[off+4])<<8 | int(b[off+5])
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

func msSince(t0, t1 time.Time) float64 {
	return float64(t1.Sub(t0).Microseconds()) / 1000.0
}

// send emits one probe.
func (s *Session) send(ctx context.Context, p *pending) {
	ttl, idx := p.probe.TTL, p.probe.Index
	switch s.Opts.Protocol {
	case ICMP:
		seq := int(atomic.AddUint32(&s.seq, 1) & 0xffff)
		p.key = fmt.Sprintf("i:%d", seq)
		payload := make([]byte, s.Opts.PacketLen)
		copy(payload, "traced.netkitty.dev")
		{
			// keep the ICMP checksum constant per flow so that per-flow load
			// balancers keep each flow on one path (Paris traceroute trick);
			// different flows get different checksums -> ECMP branches show up
			flow := idx
			if s.Opts.Paris {
				flow = 0
			}
			target := uint32(0x1000*(flow+1)) % 0xffff
			v := (target + 0xffff - uint32(seq)) % 0xffff
			payload[len(payload)-2] = byte(v >> 8)
			payload[len(payload)-1] = byte(v)
		}
		// one ICMP id per flow: NATs keep one mapping per id, so parallel
		// flows sharing an id lose their time-exceeded replies
		id := s.icmpID
		if !s.Opts.Paris {
			id = (id + idx) & 0xffff
		}
		msg := buildEcho(s.V6, id, seq, payload)
		s.register(p)
		s.writeMu.Lock()
		s.setTTL(ttl)
		p.probe.sentAt = time.Now()
		err := s.conn.WriteTo(msg, s.Dst)
		s.writeMu.Unlock()
		if err != nil {
			s.drop(p.key)
			p.complete(func(pr *Probe) { pr.Lost = true })
		}
	case UDP:
		c := s.udpConns[idx%len(s.udpConns)]
		sport := c.LocalAddr().(*net.UDPAddr).Port
		plen := s.Opts.PacketLen + ttl
		p.key = fmt.Sprintf("u:%d:%d", sport, plen+8)
		dport := s.Opts.Port
		if !s.Opts.Paris {
			dport += idx
		}
		s.register(p)
		s.writeMu.Lock()
		if s.V6 {
			_ = ipv6.NewPacketConn(c).SetHopLimit(ttl)
		} else {
			_ = ipv4.NewPacketConn(c).SetTTL(ttl)
		}
		p.probe.sentAt = time.Now()
		_, err := c.WriteToUDP(make([]byte, plen), &net.UDPAddr{IP: s.Dst, Port: dport})
		s.writeMu.Unlock()
		if err != nil {
			s.drop(p.key)
			p.complete(func(pr *Probe) { pr.Lost = true })
		}
	case TCP:
		s.sendTCP(ctx, p, ttl)
	}
}

func (s *Session) setTTL(ttl int) {
	if s.V6 {
		_ = ipv6.NewPacketConn(s.conn.c).SetHopLimit(ttl)
	} else {
		_ = ipv4.NewPacketConn(s.conn.c).SetTTL(ttl)
	}
}

func (s *Session) sendTCP(ctx context.Context, p *pending, ttl int) {
	sport := int(atomic.AddUint32(&s.port, 1))%30000 + 33000
	p.key = fmt.Sprintf("t:%d", sport)
	s.register(p)
	network := "tcp4"
	laddr := &net.TCPAddr{IP: s.src, Port: sport}
	if s.V6 {
		network = "tcp6"
	}
	d := net.Dialer{
		LocalAddr: laddr,
		Timeout:   s.Opts.Timeout,
		Control:   sockControl(ttl, s.V6, s.ifi),
	}
	dctx, cancel := context.WithTimeout(ctx, s.Opts.Timeout)
	p.probe.sentAt = time.Now()
	go func() {
		<-p.done
		cancel()
	}()
	go func() {
		defer cancel()
		c, err := d.DialContext(dctx, network, net.JoinHostPort(s.Dst.String(), fmt.Sprint(s.Opts.Port)))
		now := time.Now()
		if err == nil {
			c.Close()
			if s.take(p.key) != nil {
				p.complete(func(pr *Probe) {
					pr.IP, pr.RTT, pr.Kind, pr.Final = s.Dst.String(), msSince(pr.sentAt, now), KindTCPSynAck, true
				})
			}
			return
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			if s.take(p.key) != nil {
				p.complete(func(pr *Probe) {
					pr.IP, pr.RTT, pr.Kind, pr.Final = s.Dst.String(), msSince(pr.sentAt, now), KindTCPRst, true
				})
			}
			return
		}
		if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL) {
			s.drop(p.key)
			p.complete(func(pr *Probe) { pr.Lost = true })
		}
		// other errors (timeout / host unreachable): the ICMP receiver decides
	}()
}

// Trace runs one traceroute through the session and streams hops to cb.
//
// Probes are sent in rounds: round i sends flow i to every TTL, so a router
// never receives a burst of probes (many ISPs police ICMP per source), and
// rounds after the first stop at the destination TTL.
func (s *Session) Trace(ctx context.Context, cb func(Event)) (*Result, error) {
	o := s.Opts
	res := &Result{
		Target: o.Target, TargetIP: s.Dst.String(), Protocol: o.Protocol, Port: o.Port,
		IPv6: s.V6, Privilege: s.Privilege, Started: time.Now(),
	}
	if o.Protocol == ICMP {
		res.Port = 0
	}
	if cb != nil {
		cb(Event{Type: "start", Result: res})
	}
	s.finalTTL.Store(0)
	grid := make([][]*pending, o.MaxTTL+1)
	for ttl := o.FirstTTL; ttl <= o.MaxTTL; ttl++ {
		for i := 0; i < o.Probes; i++ {
			grid[ttl] = append(grid[ttl], &pending{probe: Probe{TTL: ttl, Index: i}, done: make(chan struct{}), sent: make(chan struct{})})
		}
	}
	markFinal := func(ttl int) {
		for {
			cur := s.finalTTL.Load()
			if cur != 0 && cur <= int32(ttl) {
				return
			}
			if s.finalTTL.CompareAndSwap(cur, int32(ttl)) {
				return
			}
		}
	}
	go func() {
		for i := 0; i < o.Probes; i++ {
			for ttl := o.FirstTTL; ttl <= o.MaxTTL; ttl++ {
				p := grid[ttl][i]
				if f := s.finalTTL.Load(); (f > 0 && int32(ttl) > f) || ctx.Err() != nil {
					p.skipped = true
					close(p.sent)
					continue
				}
				s.send(ctx, p)
				close(p.sent)
				go func(p *pending, ttl int) {
					select {
					case <-p.done:
						p.mu.Lock()
						fin := p.probe.Final
						p.mu.Unlock()
						if fin {
							markFinal(ttl)
						}
					case <-time.After(o.Timeout + time.Second):
					}
				}(p, ttl)
				sleepCtx(ctx, o.Interval)
			}
		}
	}()
	for ttl := o.FirstTTL; ttl <= o.MaxTTL; ttl++ {
		var probes []Probe
		for _, p := range grid[ttl] {
			select {
			case <-p.sent:
			case <-ctx.Done():
			}
			if p.skipped || ctx.Err() != nil {
				continue
			}
			wait := time.Until(p.probe.sentAt.Add(o.Timeout))
			select {
			case <-p.done:
			case <-time.After(wait):
				s.drop(p.key)
				p.complete(func(pr *Probe) { pr.Lost = true })
			case <-ctx.Done():
				s.drop(p.key)
				p.complete(func(pr *Probe) { pr.Lost = true })
			}
			p.mu.Lock()
			probes = append(probes, p.probe)
			p.mu.Unlock()
		}
		if len(probes) == 0 {
			break // past the destination (or cancelled)
		}
		if f := s.finalTTL.Load(); f > 0 && int32(ttl) > f {
			break
		}
		h := Aggregate(ttl, probes)
		res.Hops = append(res.Hops, h)
		if cb != nil {
			hc := h
			cb(Event{Type: "hop", Hop: &hc})
		}
		if h.Final {
			res.Reached = true
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	res.Duration = float64(time.Since(res.Started).Milliseconds())
	if cb != nil {
		cb(Event{Type: "done", Result: res})
	}
	return res, ctx.Err()
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// Run is a convenience wrapper: open a session, trace once, close.
func Run(ctx context.Context, opts Options, cb func(Event)) (*Result, error) {
	s, err := NewSession(opts)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Trace(ctx, cb)
}

func ipOrEmpty(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

var debug = os.Getenv("TRACED_DEBUG") != ""

func (m *parsedICMP) typeOr(d int) int {
	if m == nil {
		return d
	}
	return m.Type
}
func (m *parsedICMP) codeOr(d int) int {
	if m == nil {
		return d
	}
	return m.Code
}
func (m *parsedICMP) innerOr() []byte {
	if m == nil {
		return nil
	}
	return m.Inner
}
func (m *parsedICMP) mplsOr() []MPLSLabel {
	if m == nil {
		return nil
	}
	return m.MPLS
}
