//go:build linux

package trace

import (
	"net"
	"syscall"
)

const (
	sysIPv6MTUDiscover = 23
	sysIPv6PMTUDiscDo  = 2
	sysIPv6MTU         = 24
)

func bindToDevice(fd int, ifi *net.Interface, v6 bool) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifi.Name)
}

func prepareDgramICMP(fd int, v6 bool) error { return nil }

func setDontFragment(fd int, v6 bool) error {
	if v6 {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, sysIPv6MTUDiscover, sysIPv6PMTUDiscDo)
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
}

func getTCPMaxSeg(fd int) int {
	v, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func getIPMTU(fd int, v6 bool) int {
	if v6 {
		v, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_IPV6, sysIPv6MTU)
		if err == nil && v > 0 {
			return v
		}
		return 0
	}
	v, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU)
	if err == nil && v > 0 {
		return v
	}
	return 0
}
