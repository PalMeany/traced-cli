package trace

import (
	"encoding/binary"
	"net"
	"testing"
)

// quoted original datagram: IPv4 header + 8 bytes of UDP
func quotedUDP(dst net.IP, sport, dport, ulen int) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	b[8] = 1
	b[9] = 17
	copy(b[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(b[16:20], dst.To4())
	binary.BigEndian.PutUint16(b[20:], uint16(sport))
	binary.BigEndian.PutUint16(b[22:], uint16(dport))
	binary.BigEndian.PutUint16(b[24:], uint16(ulen))
	return b
}

func mplsExt(labels ...uint32) []byte {
	obj := make([]byte, 4+4*len(labels))
	binary.BigEndian.PutUint16(obj[0:], uint16(len(obj)))
	obj[2], obj[3] = 1, 1
	for i, l := range labels {
		binary.BigEndian.PutUint32(obj[4+4*i:], l)
	}
	return append([]byte{0x20, 0, 0, 0}, obj...)
}

func TestParseTimeExceededWithMPLS_RFC4884(t *testing.T) {
	dst := net.ParseIP("1.1.1.1")
	orig := quotedUDP(dst, 40000, 33434, 40)
	// pad original datagram to a multiple of 4 and set the length attribute
	for len(orig)%4 != 0 {
		orig = append(orig, 0)
	}
	msg := []byte{icmp4TimeExceeded, 0, 0, 0, 0, byte(len(orig) / 4), 0, 0}
	msg = append(msg, orig...)
	// label 24005, TC 0, S=1, TTL 1
	msg = append(msg, mplsExt(24005<<12|1<<8|1)...)
	m, ok := parseICMP(msg, false)
	if !ok || m.Type != icmp4TimeExceeded {
		t.Fatalf("parse failed: %+v", m)
	}
	if len(m.MPLS) != 1 || m.MPLS[0].Label != 24005 || !m.MPLS[0].S || m.MPLS[0].TTL != 1 {
		t.Fatalf("bad MPLS: %+v", m.MPLS)
	}
	in, ok := parseInner(m.Inner, false)
	if !ok || in.Proto != 17 || in.SrcPort != 40000 || !in.Dst.Equal(dst) {
		t.Fatalf("bad inner: %+v", in)
	}
	if l := udpLenFromInner(m.Inner, false); l != 40 {
		t.Fatalf("udp len %d", l)
	}
}

func TestParseTimeExceededCompat128(t *testing.T) {
	// pre-RFC4884 router: no length attribute, original datagram padded to 128 bytes
	orig := make([]byte, 128)
	copy(orig, quotedUDP(net.ParseIP("8.8.8.8"), 41000, 33435, 20))
	msg := append([]byte{icmp4TimeExceeded, 0, 0, 0, 0, 0, 0, 0}, orig...)
	msg = append(msg, mplsExt(16<<12|0x100|255, 17<<12|254)...)
	m, _ := parseICMP(msg, false)
	if len(m.MPLS) != 2 || m.MPLS[0].Label != 16 || m.MPLS[1].Label != 17 || m.MPLS[1].S {
		t.Fatalf("labels: %+v", m.MPLS)
	}
	if len(m.Inner) != 128 {
		t.Fatalf("inner len %d", len(m.Inner))
	}
}

func TestParseEchoAndInnerICMP(t *testing.T) {
	e := buildEcho(false, 0x1234, 77, []byte("hello"))
	if checksum(e) != 0 {
		t.Fatal("checksum does not verify")
	}
	m, ok := parseICMP(append([]byte{0}, e[1:]...), false) // as echo reply
	if !ok || m.ID != 0x1234 || m.Seq != 77 {
		t.Fatalf("echo: %+v", m)
	}
	// quoted echo request inside a time exceeded
	q := make([]byte, 20)
	q[0], q[9] = 0x45, 1
	copy(q[16:20], net.ParseIP("9.9.9.9").To4())
	q = append(q, e[:8]...)
	in, ok := parseInner(q, false)
	if !ok || in.Proto != 1 || in.Seq != 77 || in.ID != 0x1234 {
		t.Fatalf("inner echo: %+v", in)
	}
}

func TestParseInnerIPv6TCP(t *testing.T) {
	b := make([]byte, 48)
	b[0] = 0x60
	b[6] = 6
	dst := net.ParseIP("2606:4700::1111")
	copy(b[24:40], dst)
	binary.BigEndian.PutUint16(b[40:], 50000)
	binary.BigEndian.PutUint16(b[42:], 443)
	in, ok := parseInner(b, true)
	if !ok || in.Proto != 6 || in.SrcPort != 50000 || in.DstPort != 443 || !in.Dst.Equal(dst) {
		t.Fatalf("v6 inner: %+v", in)
	}
}

func TestAggregateECMP(t *testing.T) {
	h := Aggregate(7, []Probe{
		{TTL: 7, Index: 0, IP: "10.0.0.1", RTT: 5},
		{TTL: 7, Index: 1, IP: "10.0.0.2", RTT: 6},
		{TTL: 7, Index: 2, IP: "10.0.0.1", RTT: 4},
		{TTL: 7, Index: 3, Lost: true},
	})
	if !h.ECMP() || len(h.Responders) != 2 || h.Primary().IP != "10.0.0.1" {
		t.Fatalf("ecmp: %+v", h.Responders)
	}
	if h.Received != 3 || h.Sent != 4 || h.Loss() != 0.25 || h.MinRTT() != 4 {
		t.Fatalf("stats: recv %d loss %v min %v", h.Received, h.Loss(), h.MinRTT())
	}
}

func TestClassifySNI(t *testing.T) {
	r := &SNIResult{SNI: "blocked.example", Target: SNIAttempt{Outcome: SNIReset}, Control: SNIAttempt{SNI: "example.com", Outcome: SNIServerHello},
		BlockTTL: 5, DestTTL: 11, BlockHop: "10.1.1.1"}
	classifySNI(r)
	if r.Verdict != "sni-blocked" {
		t.Fatalf("verdict %s", r.Verdict)
	}
	r = &SNIResult{SNI: "x", Target: SNIAttempt{Outcome: SNIReset}, Control: SNIAttempt{Outcome: SNIServerHello}, BlockTTL: 11, DestTTL: 11}
	classifySNI(r)
	if r.Verdict != "server-rejected" {
		t.Fatalf("verdict %s", r.Verdict)
	}
	r = &SNIResult{SNI: "ok", Target: SNIAttempt{Outcome: SNIAlert}, Control: SNIAttempt{Outcome: SNIServerHello}}
	classifySNI(r)
	if r.Verdict != "ok" {
		t.Fatalf("verdict %s", r.Verdict)
	}
}
