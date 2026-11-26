//go:build darwin

package trace

import (
	"net"
	"syscall"
)

const (
	sysIPBoundIF    = 25   // IP_BOUND_IF
	sysIPv6BoundIF  = 125  // IPV6_BOUND_IF
	sysIPStripHdr   = 0x17 // IP_STRIPHDR
	sysIPDontFrag   = 28   // IP_DONTFRAG
	sysIPv6DontFrag = 62   // IPV6_DONTFRAG
)

func bindToDevice(fd int, ifi *net.Interface, v6 bool) error {
	if v6 {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, sysIPv6BoundIF, ifi.Index)
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, sysIPBoundIF, ifi.Index)
}

func prepareDgramICMP(fd int, v6 bool) error {
	if !v6 {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, sysIPStripHdr, 1)
	}
	return nil
}

func setDontFragment(fd int, v6 bool) error {
	if v6 {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, sysIPv6DontFrag, 1)
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, sysIPDontFrag, 1)
}

func getTCPMaxSeg(fd int) int {
	v, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func getIPMTU(fd int, v6 bool) int { return 0 }
