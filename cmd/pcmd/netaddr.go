package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func httpsURL(host string, port int) string {
	return "https://" + hostPort(host, port)
}

// An IPv6 literal is bracketed so the app cannot mistake it for a host:port pair.
func queryHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

// Hostnames are rejected: the bind address must name a local interface, not resolve to one.
func validateBindHost(host string) error {
	if net.ParseIP(strings.Trim(host, "[]")) == nil {
		return fmt.Errorf("--host %q is not an IP address (use e.g. 0.0.0.0, 127.0.0.1 or ::)", host)
	}
	return nil
}

// Anything but an IP address or a hostname is rejected so a typo cannot end up inside every QR code.
func validateAdvertiseHost(host string) error {
	if host == "" {
		return nil
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return nil
	}
	if isHostname(host) {
		return nil
	}
	return fmt.Errorf("--advertise-ip %q is neither an IP address nor a hostname", host)
}

func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func specificBindIP(host string) string {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// Link-local fe80:: addresses are skipped: a phone would need the scope id.
func lanIPsFrom(addrs []net.Addr) []string {
	var v4, v6 []string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ipnet.IP.To4() != nil {
			v4 = append(v4, ipnet.IP.String())
		} else if ipnet.IP.IsGlobalUnicast() {
			v6 = append(v6, ipnet.IP.String())
		}
	}
	ips := append(v4, v6...)
	if len(ips) == 0 {
		return []string{"127.0.0.1"}
	}
	return ips
}

func validateAddressFlags(flags interface {
	Changed(string) bool
	GetString(string) (string, error)
}) error {
	if flags.Changed("host") {
		host, _ := flags.GetString("host")
		if err := validateBindHost(host); err != nil {
			return err
		}
	}
	if flags.Changed("advertise-ip") {
		adv, _ := flags.GetString("advertise-ip")
		if err := validateAdvertiseHost(adv); err != nil {
			return err
		}
	}
	return nil
}
