//go:build darwin

package trace

import (
	"net"
	"syscall"
)

const (
	sysIPBoundIF   = 25  // IP_BOUND_IF
	sysIPv6BoundIF = 125 // IPV6_BOUND_IF
	sysIPStripHdr  = 0x17
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
