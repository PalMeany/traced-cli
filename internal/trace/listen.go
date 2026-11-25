package trace

import (
	"net"
	"os"
	"syscall"
)

// icmpConn is an ICMP listener (raw or unprivileged datagram socket).
type icmpConn struct {
	c   net.PacketConn
	raw bool
	v6  bool
}

// listenICMP opens an ICMP socket, optionally bound to an interface/address.
func listenICMP(v6, raw bool, ifi *net.Interface, src net.IP) (*icmpConn, error) {
	family, proto := syscall.AF_INET, syscall.IPPROTO_ICMP
	if v6 {
		family, proto = syscall.AF_INET6, syscall.IPPROTO_ICMPV6
	}
	typ := syscall.SOCK_DGRAM
	if raw {
		typ = syscall.SOCK_RAW
	}
	fd, err := syscall.Socket(family, typ, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	fail := func(e error) (*icmpConn, error) { syscall.Close(fd); return nil, e }
	if !raw {
		if err := prepareDgramICMP(fd, v6); err != nil {
			return fail(os.NewSyscallError("setsockopt", err))
		}
	}
	if ifi != nil {
		if err := bindToDevice(fd, ifi, v6); err != nil {
			return fail(os.NewSyscallError("bind-to-device", err))
		}
	}
	var sa syscall.Sockaddr
	if v6 {
		a := &syscall.SockaddrInet6{}
		if src != nil {
			copy(a.Addr[:], src.To16())
		}
		sa = a
	} else {
		a := &syscall.SockaddrInet4{}
		if src != nil {
			copy(a.Addr[:], src.To4())
		}
		sa = a
	}
	if err := syscall.Bind(fd, sa); err != nil {
		return fail(os.NewSyscallError("bind", err))
	}
	f := os.NewFile(uintptr(fd), "icmp")
	c, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	return &icmpConn{c: c, raw: raw, v6: v6}, nil
}

func (ic *icmpConn) ReadFrom(b []byte) ([]byte, net.Addr, error) {
	n, peer, err := ic.c.ReadFrom(b)
	if err != nil {
		return nil, nil, err
	}
	p := b[:n]
	// strip an IPv4 header if the platform delivered it
	if !ic.v6 && len(p) >= 20 && p[0]>>4 == 4 {
		ihl := int(p[0]&0x0f) * 4
		if ihl >= 20 && ihl <= len(p) {
			p = p[ihl:]
		}
	}
	return p, peer, nil
}

func (ic *icmpConn) WriteTo(b []byte, dst net.IP) error {
	var a net.Addr = &net.UDPAddr{IP: dst}
	if _, ok := ic.c.(*net.IPConn); ok {
		a = &net.IPAddr{IP: dst}
	}
	_, err := ic.c.WriteTo(b, a)
	return err
}

func (ic *icmpConn) Close() error { return ic.c.Close() }

// sockControl returns a Control func setting TTL and interface binding.
func sockControl(ttl int, v6 bool, ifi *net.Interface) func(string, string, syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			if ttl > 0 {
				if v6 {
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
				} else {
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
				}
				if serr != nil {
					return
				}
			}
			if ifi != nil {
				serr = bindToDevice(int(fd), ifi, v6)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// interfaceAddr returns the first address of the requested family on ifi.
func interfaceAddr(ifi *net.Interface, v6 bool) net.IP {
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if v6 && ip.To4() == nil && !ip.IsLinkLocalUnicast() {
			return ip
		}
		if !v6 && ip.To4() != nil {
			return ip.To4()
		}
	}
	return nil
}
