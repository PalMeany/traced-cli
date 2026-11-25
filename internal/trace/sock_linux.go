//go:build linux

package trace

import (
	"net"
	"syscall"
)

func bindToDevice(fd int, ifi *net.Interface, v6 bool) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifi.Name)
}

func prepareDgramICMP(fd int, v6 bool) error { return nil }
