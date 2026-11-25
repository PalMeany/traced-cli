package trace

import (
	"encoding/binary"
	"net"
)

// ICMP message types we care about.
const (
	icmp4EchoReply    = 0
	icmp4Unreachable  = 3
	icmp4EchoRequest  = 8
	icmp4TimeExceeded = 11

	icmp6Unreachable  = 1
	icmp6TimeExceeded = 3
	icmp6EchoRequest  = 128
	icmp6EchoReply    = 129
)

// parsedICMP is a decoded ICMP(v6) message.
type parsedICMP struct {
	Type, Code int
	// echo id/seq for echo replies
	ID, Seq int
	// for errors: the quoted original datagram
	Inner []byte
	MPLS  []MPLSLabel
}

// innerProbe identifies the probe quoted inside an ICMP error.
type innerProbe struct {
	Proto   int // 1 icmp, 58 icmpv6, 6 tcp, 17 udp
	Dst     net.IP
	SrcPort int
	DstPort int
	ID, Seq int // for quoted echo requests
}

// parseICMP decodes an ICMP message (without the outer IP header).
func parseICMP(b []byte, v6 bool) (*parsedICMP, bool) {
	if len(b) < 8 {
		return nil, false
	}
	m := &parsedICMP{Type: int(b[0]), Code: int(b[1])}
	isErr := false
	if v6 {
		switch m.Type {
		case icmp6EchoReply, icmp6EchoRequest:
			m.ID = int(binary.BigEndian.Uint16(b[4:6]))
			m.Seq = int(binary.BigEndian.Uint16(b[6:8]))
			return m, true
		case icmp6TimeExceeded, icmp6Unreachable:
			isErr = true
		}
	} else {
		switch m.Type {
		case icmp4EchoReply, icmp4EchoRequest:
			m.ID = int(binary.BigEndian.Uint16(b[4:6]))
			m.Seq = int(binary.BigEndian.Uint16(b[6:8]))
			return m, true
		case icmp4TimeExceeded, icmp4Unreachable:
			isErr = true
		}
	}
	if !isErr {
		return m, true
	}
	body := b[8:]
	// RFC 4884 "length" attribute: v4 -> byte 5 in 32-bit words, v6 -> byte 4 in 64-bit words
	origLen := 0
	if v6 {
		origLen = int(b[4]) * 8
	} else {
		origLen = int(b[5]) * 4
	}
	m.Inner = body
	if origLen > 0 && origLen <= len(body) {
		m.Inner = body[:origLen]
		m.MPLS = parseExtensions(body[origLen:])
	} else if len(body) > 128+4 {
		// non-compliant (pre RFC 4884) routers: original datagram is padded to 128 bytes
		if ext := parseExtensions(body[128:]); ext != nil {
			m.Inner = body[:128]
			m.MPLS = ext
		}
	}
	return m, true
}

// parseExtensions parses an ICMP extension structure (RFC 4884) and returns
// the MPLS label stack object (RFC 4950, class 1 c-type 1) if present.
func parseExtensions(b []byte) []MPLSLabel {
	if len(b) < 4 {
		return nil
	}
	if b[0]>>4 != 2 { // extension version 2
		return nil
	}
	b = b[4:]
	var labels []MPLSLabel
	for len(b) >= 4 {
		l := int(binary.BigEndian.Uint16(b[0:2]))
		class, ctype := b[2], b[3]
		if l < 4 || l > len(b) {
			break
		}
		obj := b[4:l]
		if class == 1 && ctype == 1 {
			for len(obj) >= 4 {
				v := binary.BigEndian.Uint32(obj[:4])
				labels = append(labels, MPLSLabel{
					Label: int(v >> 12),
					TC:    int(v>>9) & 0x7,
					S:     v&0x100 != 0,
					TTL:   int(v & 0xff),
				})
				obj = obj[4:]
			}
		}
		b = b[l:]
	}
	return labels
}

// parseInner decodes the quoted original datagram of an ICMP error.
func parseInner(b []byte, v6 bool) (*innerProbe, bool) {
	p := &innerProbe{}
	var l4 []byte
	if v6 {
		if len(b) < 40 {
			return nil, false
		}
		p.Proto = int(b[6])
		p.Dst = net.IP(append([]byte(nil), b[24:40]...))
		l4 = b[40:]
	} else {
		if len(b) < 20 || b[0]>>4 != 4 {
			return nil, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return nil, false
		}
		p.Proto = int(b[9])
		p.Dst = net.IP(append([]byte(nil), b[16:20]...))
		l4 = b[ihl:]
	}
	if len(l4) < 8 {
		return nil, false
	}
	switch p.Proto {
	case 6, 17:
		p.SrcPort = int(binary.BigEndian.Uint16(l4[0:2]))
		p.DstPort = int(binary.BigEndian.Uint16(l4[2:4]))
	case 1, 58:
		p.ID = int(binary.BigEndian.Uint16(l4[4:6]))
		p.Seq = int(binary.BigEndian.Uint16(l4[6:8]))
	}
	return p, true
}

// buildEcho builds an ICMP(v6) echo request. For v6 the kernel fills the checksum.
func buildEcho(v6 bool, id, seq int, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	if v6 {
		b[0] = icmp6EchoRequest
	} else {
		b[0] = icmp4EchoRequest
	}
	binary.BigEndian.PutUint16(b[4:6], uint16(id))
	binary.BigEndian.PutUint16(b[6:8], uint16(seq))
	copy(b[8:], payload)
	if !v6 {
		binary.BigEndian.PutUint16(b[2:4], checksum(b))
	}
	return b
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}
