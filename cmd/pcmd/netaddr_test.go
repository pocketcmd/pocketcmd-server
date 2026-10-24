package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestURLBuilders_BracketIPv6(t *testing.T) {
	if got := pairURL("fd00::1", 8767, "tok", "fp"); got != "pocketcmd://[fd00::1]:8767/tok#fp" {
		t.Errorf("pairURL = %q", got)
	}
	if got := pairURL("192.168.1.5", 8767, "tok", "fp"); got != "pocketcmd://192.168.1.5:8767/tok#fp" {
		t.Errorf("pairURL v4 = %q", got)
	}
	if got := inviteURL("2001:db8::7", 9000, "code", "fp"); got != "pocketcmd://invite?host=[2001:db8::7]&port=9000&code=code#fp" {
		t.Errorf("inviteURL = %q", got)
	}
	if got := syncURL("myhost.lan", 9000, "tok", "fp"); got != "pocketcmd://ssh-sync?host=myhost.lan&port=9000&token=tok#fp" {
		t.Errorf("syncURL = %q", got)
	}
	if got := httpsURL("::1", 8767); got != "https://[::1]:8767" {
		t.Errorf("httpsURL = %q", got)
	}
}

func TestValidateBindHost(t *testing.T) {
	for _, ok := range []string{"0.0.0.0", "127.0.0.1", "::", "::1", "fd00::1", "[fd00::1]"} {
		if err := validateBindHost(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "localhost", "example.com", "1.2.3", "0.0.0.0:80", "garbage!"} {
		if err := validateBindHost(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestValidateAdvertiseHost(t *testing.T) {
	for _, ok := range []string{"", "10.0.0.5", "fd00::1", "nas", "nas.local", "server-1.example.com"} {
		if err := validateAdvertiseHost(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"https://nas", "nas:8767", "nas/", "-nas", "nas.", "a b", strings.Repeat("a", 64) + ".com"} {
		if err := validateAdvertiseHost(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestLanIPsFrom_IPv4ThenGlobalIPv6(t *testing.T) {
	cidr := func(s string) net.Addr {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		ip, _, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	addrs := []net.Addr{
		cidr("fe80::1/64"),
		cidr("2001:db8::5/64"),
		cidr("127.0.0.1/8"),
		cidr("192.168.1.10/24"),
		cidr("::1/128"),
		cidr("fd12:3456::9/64"),
		cidr("10.0.0.3/8"),
		&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4)},
	}
	got := lanIPsFrom(addrs)
	want := []string{"192.168.1.10", "10.0.0.3", "2001:db8::5", "fd12:3456::9"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := lanIPsFrom(nil); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("empty list must fall back to loopback, got %v", got)
	}
}

func TestRootRejectsBadAddressFlags(t *testing.T) {
	if _, _, err := runCLI(t, "list-devices", "--host", "nope"); err == nil || !strings.Contains(err.Error(), "--host") {
		t.Fatalf("expected --host validation error, got %v", err)
	}
	if _, _, err := runCLI(t, "invite", "--advertise-ip", "http://x"); err == nil || !strings.Contains(err.Error(), "--advertise-ip") {
		t.Fatalf("expected --advertise-ip validation error, got %v", err)
	}
}

func TestListenError_PortInUse(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	_, bindErr := net.Listen("tcp", l.Addr().String())
	if bindErr == nil {
		t.Fatal("expected the second bind to fail")
	}
	got := listenError(bindErr, port)
	if !strings.Contains(got.Error(), "already in use") || !strings.Contains(got.Error(), "pcmd status") || !strings.Contains(got.Error(), "--port") {
		t.Fatalf("unexpected message: %v", got)
	}
	other := listenError(errors.New("permission denied"), 80)
	if !strings.Contains(other.Error(), "listen: permission denied") {
		t.Fatalf("other errors are wrapped as is: %v", other)
	}
}

func TestSpecificBindIP(t *testing.T) {
	for host, want := range map[string]string{
		"192.168.1.20": "192.168.1.20",
		"[fd00::1]":    "fd00::1",
		"0.0.0.0":      "",
		"::":           "",
		"":             "",
		"not-an-ip":    "",
	} {
		if got := specificBindIP(host); got != want {
			t.Errorf("specificBindIP(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestResolveAdvertiseIP(t *testing.T) {
	if got := resolveAdvertiseIP("myhome.example.net", "192.168.1.20"); got != "myhome.example.net" {
		t.Errorf("explicit advertise address ignored: %q", got)
	}
	if got := resolveAdvertiseIP("", "192.168.1.20"); got != "192.168.1.20" {
		t.Errorf("bind address not advertised: %q", got)
	}
	if got := resolveAdvertiseIP("", "0.0.0.0"); got != getAllLANIPs()[0] {
		t.Errorf("wildcard bind: got %q, want the preferred LAN address", got)
	}
	if got := reachableIPs("10.8.0.1"); len(got) != 1 || got[0] != "10.8.0.1" {
		t.Errorf("reachableIPs(10.8.0.1) = %v, want only that address", got)
	}
}
