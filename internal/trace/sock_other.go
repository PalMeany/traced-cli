//go:build !darwin && !linux

package trace

import (
	"errors"
	"net"
)

func bindToDevice(fd int, ifi *net.Interface, v6 bool) error {
	return errors.New("binding to an interface is not supported on this OS")
}

func prepareDgramICMP(fd int, v6 bool) error { return nil }

func setDontFragment(fd int, v6 bool) error {
	return errors.New("DF flag is not supported on this OS")
}

func getTCPMaxSeg(fd int) int      { return 0 }
func getIPMTU(fd int, v6 bool) int { return 0 }
