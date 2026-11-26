package trace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// MTUOptions configure a Path MTU probe.
type MTUOptions struct {
	Target    string
	Port      int // TCP port (default 443)
	IPv4      bool
	IPv6      bool
	MaxMTU    int           // starting size (default 1500)
	MinMTU    int           // floor (default 576 for v4, 1280 for v6)
	Timeout   time.Duration // per-probe timeout (default 1200ms)
	Interface string
	Hops      []Hop // optional trace hops for identifying the drop hop
}

// MTUStep is one probe in the 20 -> 5 -> 1 staircase search.
type MTUStep struct {
	Size       int     `json:"size"`
	Step       int     `json:"step"` // 20 | 5 | 1
	Passed     bool    `json:"passed"`
	RTT        float64 `json:"rtt_ms,omitempty"`
	HopIP      string  `json:"hop_ip,omitempty"`
	NextHopMTU int     `json:"next_hop_mtu,omitempty"`
	Error      string  `json:"error,omitempty"`
}

// MTUProbeResult is the outcome for one protocol (ICMP or TCP).
type MTUProbeResult struct {
	Proto       string    `json:"proto"` // icmp | tcp
	PathMTU     int       `json:"path_mtu,omitempty"`
	MSS         int       `json:"mss,omitempty"`          // TCP negotiated MSS
	MSSMTU      int       `json:"mss_mtu,omitempty"`      // MSS + IP/TCP headers
	ReportedMTU int       `json:"reported_mtu,omitempty"` // ICMP FragNeeded / PTB reported MTU
	DropHopTTL  int       `json:"drop_hop_ttl,omitempty"`
	DropHopIP   string    `json:"drop_hop_ip,omitempty"`
	Steps       []MTUStep `json:"steps,omitempty"`
	Error       string    `json:"error,omitempty"`
	Note        string    `json:"note,omitempty"`
}

// MTUResult combines ICMP (DF) and TCP (MSS/PMTUD) path MTU measurements.
type MTUResult struct {
	Target   string          `json:"target"`
	TargetIP string          `json:"target_ip"`
	IPv6     bool            `json:"ipv6,omitempty"`
	Port     int             `json:"port,omitempty"`
	PathMTU  int             `json:"path_mtu,omitempty"` // conservative effective path MTU
	ICMP     *MTUProbeResult `json:"icmp,omitempty"`
	TCP      *MTUProbeResult `json:"tcp,omitempty"`
	Duration float64         `json:"duration_ms"`
}

// MTUSearch runs the 20 -> 5 -> 1 staircase algorithm:
//  1. Descend from maxMTU in steps of 20 until a packet passes (or minMTU is reached).
//  2. Ascend from firstPass+5 in steps of 5 (strictly below lastFail) to narrow to 5 bytes.
//  3. Ascend from bestPass+1 in steps of 1 (strictly below lastFail) to find the exact byte.
func MTUSearch(minMTU, maxMTU int, probe func(size int) MTUStep) (int, []MTUStep) {
	if maxMTU < minMTU {
		maxMTU = minMTU
	}
	var steps []MTUStep
	record := func(sz, stepSize int) MTUStep {
		st := probe(sz)
		st.Size = sz
		st.Step = stepSize
		steps = append(steps, st)
		return st
	}

	// Phase 1: step 20 downwards from maxMTU
	lastFail := 0
	bestPass := 0
	for sz := maxMTU; sz >= minMTU; sz -= 20 {
		st := record(sz, 20)
		if st.Passed {
			bestPass = sz
			break
		}
		lastFail = sz
		if sz == minMTU {
			break
		}
		if sz-20 < minMTU {
			st2 := record(minMTU, 20)
			if st2.Passed {
				bestPass = minMTU
			}
			break
		}
	}
	if bestPass == 0 {
		return 0, steps
	}
	if bestPass == maxMTU || lastFail == 0 {
		return bestPass, steps
	}

	// Phase 2: step 5 upwards from bestPass+5 while < lastFail
	hi := lastFail
	for sz := bestPass + 5; sz < hi; sz += 5 {
		st := record(sz, 5)
		if st.Passed {
			bestPass = sz
		} else {
			hi = sz
			break
		}
	}

	// Phase 3: step 1 upwards from bestPass+1 while < hi
	for sz := bestPass + 1; sz < hi; sz++ {
		st := record(sz, 1)
		if st.Passed {
			bestPass = sz
		} else {
			break
		}
	}
	return bestPass, steps
}

// ProbeMTU measures Path MTU to target using both ICMP (DF, 20->5->1 staircase)
// and TCP (MSS + PMTUD 20->5->1 staircase).
func ProbeMTU(ctx context.Context, o MTUOptions) (*MTUResult, error) {
	t0 := time.Now()
	dst, err := ResolveTarget(o.Target, o.IPv4, o.IPv6)
	if err != nil {
		return nil, err
	}
	v6 := dst.To4() == nil
	if o.Port <= 0 {
		o.Port = 443
	}
	if o.MaxMTU <= 0 {
		o.MaxMTU = 1500
	}
	if o.MinMTU <= 0 {
		if v6 {
			o.MinMTU = 1280
		} else {
			o.MinMTU = 576
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = 1200 * time.Millisecond
	}
	var ifi *net.Interface
	var srcIP net.IP
	if o.Interface != "" && o.Interface != "none" && o.Interface != "auto" {
		if x, ierr := net.InterfaceByName(o.Interface); ierr == nil {
			ifi = x
			srcIP = interfaceAddr(ifi, v6)
		}
	}

	res := &MTUResult{
		Target:   o.Target,
		TargetIP: dst.String(),
		IPv6:     v6,
		Port:     o.Port,
	}

	res.ICMP = probeICMPMTU(ctx, dst, v6, ifi, srcIP, o)
	res.TCP = probeTCPMTU(ctx, dst, v6, ifi, o)

	// Pick conservative effective PathMTU
	switch {
	case res.ICMP != nil && res.ICMP.PathMTU > 0 && res.TCP != nil && res.TCP.PathMTU > 0:
		if res.ICMP.PathMTU < res.TCP.PathMTU {
			res.PathMTU = res.ICMP.PathMTU
		} else {
			res.PathMTU = res.TCP.PathMTU
		}
	case res.ICMP != nil && res.ICMP.PathMTU > 0:
		res.PathMTU = res.ICMP.PathMTU
	case res.TCP != nil && res.TCP.PathMTU > 0:
		res.PathMTU = res.TCP.PathMTU
	}
	res.Duration = float64(time.Since(t0).Microseconds()) / 1000.0
	return res, nil
}

func probeICMPMTU(ctx context.Context, dst net.IP, v6 bool, ifi *net.Interface, srcIP net.IP, o MTUOptions) *MTUProbeResult {
	out := &MTUProbeResult{Proto: "icmp"}
	ic, err := listenICMP(v6, true, ifi, srcIP)
	if err != nil {
		ic, err = listenICMP(v6, false, ifi, srcIP)
		if err != nil {
			out.Error = "icmp socket: " + err.Error()
			return out
		}
	}
	defer ic.Close()

	// Enable Don't Fragment on the socket
	if sc, ok := ic.c.(syscall.Conn); ok {
		if rc, rerr := sc.SyscallConn(); rerr == nil {
			var dfErr error
			_ = rc.Control(func(fd uintptr) {
				dfErr = setDontFragment(int(fd), v6)
			})
			if dfErr != nil {
				out.Note = "DF sockopt warning: " + dfErr.Error()
			}
		}
	}

	ipHdr := 20
	if v6 {
		ipHdr = 40
	}
	id := os.Getpid() & 0xffff
	if id == 0 {
		id = 0x4d54
	}
	seq := 1

	sendAndWait := func(size int, ttl int) MTUStep {
		st := MTUStep{Size: size}
		if ctx.Err() != nil {
			st.Error = "cancelled"
			return st
		}
		payloadLen := size - ipHdr - 8
		if payloadLen < 0 {
			payloadLen = 0
		}
		if ttl > 0 {
			setSocketTTL(ic.c, ttl, v6)
		} else {
			setSocketTTL(ic.c, 64, v6)
		}
		curSeq := seq
		seq++
		pkt := buildEcho(v6, id, curSeq, make([]byte, payloadLen))
		tStart := time.Now()
		if err := ic.WriteTo(pkt, dst); err != nil {
			if isMsgSizeErr(err) {
				st.Error = "EMSGSIZE (local MTU)"
				return st
			}
			st.Error = err.Error()
			return st
		}
		deadline := tStart.Add(o.Timeout)
		buf := make([]byte, 4096)
		for {
			if ctx.Err() != nil {
				st.Error = "cancelled"
				return st
			}
			_ = ic.c.SetReadDeadline(deadline)
			p, peer, rerr := ic.ReadFrom(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					st.Error = "timeout"
					return st
				}
				st.Error = rerr.Error()
				return st
			}
			m, ok := parseICMP(p, v6)
			if !ok {
				continue
			}
			peerIP := ""
			if ip := addrIP(peer); ip != nil {
				peerIP = ip.String()
			}
			// Echo Reply from destination
			if (!v6 && m.Type == icmp4EchoReply) || (v6 && m.Type == icmp6EchoReply) {
				if m.Seq == curSeq && (!ic.raw || m.ID == id) {
					st.Passed = true
					st.RTT = float64(time.Since(tStart).Microseconds()) / 1000.0
					st.HopIP = peerIP
					return st
				}
				continue
			}
			// ICMPv4 Fragmentation Needed (type 3 code 4) or ICMPv6 Packet Too Big (type 2)
			if (!v6 && m.Type == icmp4Unreachable && m.Code == 4) || (v6 && m.Type == 2) {
				st.HopIP = peerIP
				st.RTT = float64(time.Since(tStart).Microseconds()) / 1000.0
				if !v6 && len(p) >= 8 {
					st.NextHopMTU = int(binary.BigEndian.Uint16(p[6:8]))
				} else if v6 && len(p) >= 8 {
					st.NextHopMTU = int(binary.BigEndian.Uint32(p[4:8]))
				}
				st.Error = "fragmentation needed"
				return st
			}
			// Time Exceeded when doing TTL drop-hop search
			if ttl > 0 && ((!v6 && m.Type == icmp4TimeExceeded) || (v6 && m.Type == icmp6TimeExceeded)) {
				st.Passed = true
				st.HopIP = peerIP
				st.RTT = float64(time.Since(tStart).Microseconds()) / 1000.0
				return st
			}
		}
	}

	mtu, steps := MTUSearch(o.MinMTU, o.MaxMTU, func(size int) MTUStep {
		return sendAndWait(size, 0)
	})
	out.PathMTU = mtu
	out.Steps = steps

	for _, st := range steps {
		if !st.Passed && st.NextHopMTU > 0 && out.ReportedMTU == 0 {
			out.ReportedMTU = st.NextHopMTU
		}
		if !st.Passed && st.HopIP != "" && out.DropHopIP == "" {
			out.DropHopIP = st.HopIP
		}
	}

	// Match drop hop TTL from trace hops if we already know DropHopIP
	if out.DropHopIP != "" && len(o.Hops) > 0 {
		for _, h := range o.Hops {
			for _, rs := range h.Responders {
				if rs.IP == out.DropHopIP {
					out.DropHopTTL = h.TTL
					break
				}
			}
		}
	}

	// If PathMTU < MaxMTU and no router sent FragNeeded (PMTUD blackhole),
	// locate the first TTL where a packet of size PathMTU+1 fails to elicit TimeExceeded.
	if out.PathMTU > 0 && out.PathMTU < o.MaxMTU && out.DropHopIP == "" && ctx.Err() == nil {
		testSize := out.PathMTU + 1
		if testSize > o.MaxMTU {
			testSize = o.MaxMTU
		}
		maxTTL := 20
		if len(o.Hops) > 0 && len(o.Hops) < maxTTL {
			maxTTL = len(o.Hops)
		}
		lastOKTTL := 0
		lastOKIP := ""
		for ttl := 1; ttl <= maxTTL; ttl++ {
			if ctx.Err() != nil {
				break
			}
			st := sendAndWait(testSize, ttl)
			if st.Passed {
				lastOKTTL = ttl
				if st.HopIP != "" {
					lastOKIP = st.HopIP
				}
				if st.HopIP == dst.String() {
					break
				}
			} else {
				out.DropHopTTL = ttl
				if st.HopIP != "" {
					out.DropHopIP = st.HopIP
				} else if ttl-1 >= 0 && ttl-1 < len(o.Hops) && len(o.Hops[ttl-1].Responders) > 0 {
					out.DropHopIP = o.Hops[ttl-1].Responders[0].IP
				} else if lastOKIP != "" {
					out.Note = fmt.Sprintf("drops after hop %d (%s)", lastOKTTL, lastOKIP)
				}
				break
			}
		}
	}

	if out.PathMTU == 0 && out.Error == "" {
		out.Error = "no ICMP echo replies (host may block ICMP)"
	}
	return out
}

func probeTCPMTU(ctx context.Context, dst net.IP, v6 bool, ifi *net.Interface, o MTUOptions) *MTUProbeResult {
	out := &MTUProbeResult{Proto: "tcp"}
	hdrOverhead := 40 // IPv4(20) + TCP(20)
	if v6 {
		hdrOverhead = 60 // IPv6(40) + TCP(20)
	}
	addr := net.JoinHostPort(dst.String(), strconv.Itoa(o.Port))

	dialOne := func(timeout time.Duration) (net.Conn, int, int, error) {
		var mss, ipMTU int
		d := net.Dialer{
			Timeout: timeout,
			Control: func(_, _ string, rc syscall.RawConn) error {
				var serr error
				_ = rc.Control(func(fd uintptr) {
					_ = setDontFragment(int(fd), v6)
					if ifi != nil {
						serr = bindToDevice(int(fd), ifi, v6)
					}
				})
				return serr
			},
		}
		netw := "tcp4"
		if v6 {
			netw = "tcp6"
		}
		c, err := d.DialContext(ctx, netw, addr)
		if err != nil {
			return nil, 0, 0, err
		}
		if sc, ok := c.(syscall.Conn); ok {
			if rc, rerr := sc.SyscallConn(); rerr == nil {
				_ = rc.Control(func(fd uintptr) {
					mss = getTCPMaxSeg(int(fd))
					ipMTU = getIPMTU(int(fd), v6)
				})
			}
		}
		return c, mss, ipMTU, nil
	}

	// Step 1: initial TCP handshake to inspect negotiated MSS & kernel PMTU
	c, mss, ipMTU, err := dialOne(2500 * time.Millisecond)
	if err != nil && o.Port == 443 {
		// Fallback to port 80 if 443 is refused/filtered
		addr = net.JoinHostPort(dst.String(), "80")
		c, mss, ipMTU, err = dialOne(2500 * time.Millisecond)
	}
	if err != nil {
		out.Error = "tcp dial: " + err.Error()
		return out
	}
	c.Close()

	out.MSS = mss
	if mss > 0 {
		out.MSSMTU = mss + hdrOverhead
	}

	// Effective upper bound for TCP PMTUD staircase: we test up to MaxMTU
	// using a TCP connection with DF set and a padded TLS ClientHello / payload
	// of size (targetMTU - hdrOverhead). If the peer responds (TLS ServerHello /
	// alert / HTTP / FIN / RST) without write EMSGSIZE or timeout, that MTU passed.
	tcpProbeSize := func(size int) MTUStep {
		st := MTUStep{Size: size}
		if ctx.Err() != nil {
			st.Error = "cancelled"
			return st
		}
		// A TCP segment cannot exceed negotiated MSS + headers on a single packet;
		// if negotiated MSS already caps MTU below size, record that explicitly.
		if out.MSSMTU > 0 && size > out.MSSMTU {
			st.Error = fmt.Sprintf("exceeds negotiated TCP MSS (%d → MTU %d)", out.MSS, out.MSSMTU)
			return st
		}
		payloadLen := size - hdrOverhead
		if payloadLen < 64 {
			payloadLen = 64
		}
		tStart := time.Now()
		conn, _, kmtu, derr := dialOne(o.Timeout)
		if derr != nil {
			st.Error = derr.Error()
			return st
		}
		defer conn.Close()
		if kmtu > 0 && size > kmtu {
			st.NextHopMTU = kmtu
			st.Error = fmt.Sprintf("kernel PMTU %d", kmtu)
			return st
		}
		_ = conn.SetDeadline(time.Now().Add(o.Timeout))
		// Build a padded HTTP-like or TLS-like payload of exact payloadLen bytes
		// so the kernel emits a full-sized TCP segment with DF=1.
		buf := make([]byte, payloadLen)
		copy(buf, []byte("GET / HTTP/1.1\r\nHost: "+o.Target+"\r\nX-Pad: "))
		for i := len("GET / HTTP/1.1\r\nHost: " + o.Target + "\r\nX-Pad: "); i < payloadLen-4; i++ {
			buf[i] = 'a'
		}
		if payloadLen >= 4 {
			copy(buf[payloadLen-4:], []byte("\r\n\r\n"))
		}
		if _, werr := conn.Write(buf); werr != nil {
			if isMsgSizeErr(werr) {
				st.Error = "EMSGSIZE"
				return st
			}
			st.Error = werr.Error()
			return st
		}
		rb := make([]byte, 256)
		n, rerr := conn.Read(rb)
		st.RTT = float64(time.Since(tStart).Microseconds()) / 1000.0
		if n > 0 || rerr != nil && !isTimeoutErr(rerr) {
			// Any peer reply (data, EOF, RST) proves the full-size TCP segment reached the peer!
			st.Passed = true
			return st
		}
		st.Error = "timeout (PMTUD blackhole or no reply)"
		return st
	}

	mtu, steps := MTUSearch(o.MinMTU, o.MaxMTU, tcpProbeSize)
	out.PathMTU = mtu
	out.Steps = steps
	if out.PathMTU == 0 && out.MSSMTU > 0 {
		out.PathMTU = out.MSSMTU
		out.Note = "derived from negotiated TCP MSS (payload probes timed out)"
	} else if ipMTU > 0 && (out.PathMTU == 0 || ipMTU < out.PathMTU) {
		out.PathMTU = ipMTU
		out.ReportedMTU = ipMTU
	}
	return out
}

func setSocketTTL(c net.PacketConn, ttl int, v6 bool) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		if v6 {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		} else {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
}

func isMsgSizeErr(err error) bool {
	if errors.Is(err, syscall.EMSGSIZE) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "message too long") || strings.Contains(s, "emsgsize")
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
