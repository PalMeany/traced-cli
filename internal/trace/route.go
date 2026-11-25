package trace

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// IsTunnelIface reports whether an interface name looks like a VPN/TUN device.
func IsTunnelIface(name string) bool {
	for _, p := range []string{"utun", "tun", "tap", "wg", "ppp", "ipsec", "zt", "tailscale"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// RouteIface returns the interface the OS uses to reach dst ("" if unknown).
func RouteIface(dst net.IP) string {
	var out []byte
	var err error
	switch runtime.GOOS {
	case "darwin":
		args := []string{"-n", "get"}
		if dst.To4() == nil {
			args = append(args, "-inet6")
		}
		out, err = exec.Command("route", append(args, dst.String())...).Output()
		if err != nil {
			return ""
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(l, "interface:") {
				return strings.TrimSpace(strings.TrimPrefix(l, "interface:"))
			}
		}
	case "linux":
		out, err = exec.Command("ip", "route", "get", dst.String()).Output()
		if err != nil {
			return ""
		}
		f := strings.Fields(string(out))
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return f[i+1]
			}
		}
	}
	return ""
}

// PhysicalDefaultIface returns the first default-route interface that is not a tunnel.
func PhysicalDefaultIface(v6 bool) string {
	switch runtime.GOOS {
	case "darwin":
		fam := "inet"
		if v6 {
			fam = "inet6"
		}
		out, err := exec.Command("netstat", "-rn", "-f", fam).Output()
		if err != nil {
			return ""
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) >= 4 && f[0] == "default" {
				ifn := f[3]
				if !IsTunnelIface(ifn) && !strings.HasPrefix(f[1], "link#") && !strings.HasPrefix(f[1], "fe80::%utun") {
					return ifn
				}
			}
		}
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return ""
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "dev" && !IsTunnelIface(f[i+1]) {
					return f[i+1]
				}
			}
		}
	}
	return ""
}

// AutoInterface picks the interface for "auto" mode: when the route to dst
// goes through a VPN/TUN device and a physical default route exists, the
// physical interface is returned (TUN stacks often fake ICMP replies).
func AutoInterface(dst net.IP) (iface, tunnel string) {
	r := RouteIface(dst)
	if r == "" || !IsTunnelIface(r) {
		return "", ""
	}
	p := PhysicalDefaultIface(dst.To4() == nil)
	if p == "" {
		return "", r
	}
	return p, r
}
