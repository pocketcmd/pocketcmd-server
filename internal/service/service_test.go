package service

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestDetectOS(t *testing.T) {
	os := DetectOS()
	if os != "linux" && os != "darwin" {
		t.Fatalf("unexpected OS: %s", os)
	}
}

func TestIsInstalled_NotInstalled(t *testing.T) {
	result := IsInstalled()
	_ = result

	p := ServiceFilePath()
	_, err := os.Stat(p)
	if err != nil {
		if result {
			t.Fatal("IsInstalled returned true but service file does not exist")
		}
	}
}

func TestGenerateSystemdUnit(t *testing.T) {
	unit := GenerateSystemdUnit("/usr/local/bin/pcmd", 8767, "127.0.0.1")
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/pcmd --foreground") {
		t.Fatal("missing ExecStart")
	}
	if !strings.Contains(unit, "-p 8767") {
		t.Fatal("missing port flag")
	}
	if !strings.Contains(unit, "--host 127.0.0.1") {
		t.Fatal("missing host flag")
	}
	if !strings.Contains(unit, "[Service]") {
		t.Fatal("missing [Service] section")
	}
	if !strings.Contains(unit, "[Unit]") {
		t.Fatal("missing [Unit] section")
	}
	if !strings.Contains(unit, "[Install]") {
		t.Fatal("missing [Install] section")
	}
	if !strings.Contains(unit, "Restart=always") {
		t.Fatal("missing Restart directive")
	}
}

func TestGenerateLaunchdPlist(t *testing.T) {
	plist := GenerateLaunchdPlist("/usr/local/bin/pcmd", 8767, "127.0.0.1")
	if !strings.Contains(plist, "/usr/local/bin/pcmd") {
		t.Fatal("missing binary path")
	}
	if !strings.Contains(plist, "com.pocketcmd.server") {
		t.Fatal("missing label")
	}
	if !strings.Contains(plist, "<key>KeepAlive</key>") {
		t.Fatal("missing KeepAlive")
	}
	if !strings.Contains(plist, "<key>RunAtLoad</key>") {
		t.Fatal("missing RunAtLoad")
	}
	if !strings.Contains(plist, "8767") {
		t.Fatal("missing port")
	}
	if !strings.Contains(plist, "127.0.0.1") {
		t.Fatal("missing host")
	}
}

func TestServicePaths(t *testing.T) {
	if runtime.GOOS == "linux" {
		p := SystemdUnitPath()
		if !strings.Contains(p, "systemd/user/pocketcmd.service") {
			t.Fatalf("unexpected systemd path: %s", p)
		}
	}
	if runtime.GOOS == "darwin" {
		p := LaunchdPlistPath()
		if !strings.Contains(p, "LaunchAgents/com.pocketcmd.server.plist") {
			t.Fatalf("unexpected launchd path: %s", p)
		}
	}
}

func TestInstallDryRun(t *testing.T) {
	dir := t.TempDir()
	binPath := "/usr/local/bin/pcmd"
	port := 8767
	host := "127.0.0.1"

	if runtime.GOOS == "linux" {
		unitPath := filepath.Join(dir, "pocketcmd.service")
		unit := GenerateSystemdUnit(binPath, port, host)
		if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(unitPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "ExecStart") {
			t.Fatal("service file missing ExecStart")
		}
	}

	if runtime.GOOS == "darwin" {
		plistPath := filepath.Join(dir, "com.pocketcmd.server.plist")
		plist := GenerateLaunchdPlist(binPath, port, host)
		if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(plistPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "ProgramArguments") {
			t.Fatal("plist file missing ProgramArguments")
		}
	}
}

func TestGenerateSystemdUnit_Content(t *testing.T) {
	unit := GenerateSystemdUnit("/opt/pcmd/bin/server", 9999, "0.0.0.0")

	checks := map[string]string{
		"ExecStart":  "ExecStart=/opt/pcmd/bin/server --foreground -p 9999 --host 0.0.0.0",
		"Restart":    "Restart=always",
		"RestartSec": "RestartSec=5",
		"WantedBy":   "WantedBy=default.target",
		"Desc":       "Description=PocketCmd Server",
		"After":      "After=network.target",
	}
	for name, expected := range checks {
		if !strings.Contains(unit, expected) {
			t.Fatalf("%s: expected %q in unit file", name, expected)
		}
	}
}

func TestGenerateLaunchdPlist_Content(t *testing.T) {
	plist := GenerateLaunchdPlist("/opt/pcmd/bin/server", 9999, "0.0.0.0")

	if !strings.Contains(plist, "<string>/opt/pcmd/bin/server</string>") {
		t.Fatal("missing binary in ProgramArguments")
	}
	if !strings.Contains(plist, "<string>--foreground</string>") {
		t.Fatal("missing --foreground in ProgramArguments")
	}
	if !strings.Contains(plist, "<string>-p</string>") {
		t.Fatal("missing -p in ProgramArguments")
	}
	if !strings.Contains(plist, "<string>9999</string>") {
		t.Fatal("missing port in ProgramArguments")
	}
	if !strings.Contains(plist, "<string>--host</string>") {
		t.Fatal("missing --host in ProgramArguments")
	}
	if !strings.Contains(plist, "<string>0.0.0.0</string>") {
		t.Fatal("missing host in ProgramArguments")
	}
	if !strings.Contains(plist, "<?xml version") {
		t.Fatal("missing XML header")
	}
	if !strings.Contains(plist, "com.pocketcmd.server") {
		t.Fatal("missing label")
	}

	home, _ := os.UserHomeDir()
	expectedLog := filepath.Join(home, ".pocketcmd", "server.log")
	if !strings.Contains(plist, expectedLog) {
		t.Fatalf("missing log path %q", expectedLog)
	}
}

func TestServiceFilePath_CurrentOS(t *testing.T) {
	p := ServiceFilePath()
	if p == "" {
		t.Fatal("ServiceFilePath returned empty string")
	}
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(p, home) {
		t.Fatalf("expected path under home dir, got %s", p)
	}

	switch runtime.GOOS {
	case "linux":
		if !strings.HasSuffix(p, "pocketcmd.service") {
			t.Fatalf("linux: expected .service suffix, got %s", p)
		}
	case "darwin":
		if !strings.HasSuffix(p, "com.pocketcmd.server.plist") {
			t.Fatalf("darwin: expected .plist suffix, got %s", p)
		}
	}
}

func TestStatus_NotInstalled(t *testing.T) {
	s := GetStatus()
	p := ServiceFilePath()
	if _, err := os.Stat(p); err != nil {
		if s.Running {
			t.Fatal("expected Running=false when service is not installed")
		}
		if s.Installed {
			t.Fatal("expected Installed=false when service file does not exist")
		}
	}
}

func TestHealthCheck_NoServer(t *testing.T) {
	err := HealthCheck("127.0.0.1", 19999)
	if err == nil {
		t.Fatal("expected error from HealthCheck with no server running")
	}
}

func TestHealthCheck_ProbesTheBindAddress(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if err := HealthCheck(host, port); err != nil {
		t.Fatalf("HealthCheck(%s, %d) = %v, want nil", host, port, err)
	}
	if err := HealthCheck("0.0.0.0", port); err != nil {
		t.Fatalf("HealthCheck(0.0.0.0, %d) = %v, want nil", port, err)
	}
}

func TestProbeHost(t *testing.T) {
	for host, want := range map[string]string{
		"192.168.1.20": "192.168.1.20",
		"0.0.0.0":      "127.0.0.1",
		"":             "127.0.0.1",
		"::":           "::1",
		"[::]":         "::1",
		"fd00::1":      "fd00::1",
		"[fd00::1]":    "fd00::1",
	} {
		if got := probeHost(host); got != want {
			t.Errorf("probeHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestDetectInitSystem(t *testing.T) {
	result := DetectInitSystem()
	valid := map[string]bool{"systemd": true, "openrc": true, "none": true}
	if !valid[result] {
		t.Fatalf("DetectInitSystem returned unexpected value: %q, want one of systemd, openrc, none", result)
	}
}

func TestGenerateOpenRCScript(t *testing.T) {
	script := GenerateOpenRCScript("/usr/local/bin/pcmd", 8767, "0.0.0.0", "alice", "/home/alice")

	if !strings.Contains(script, "#!/sbin/openrc-run") {
		t.Fatal("missing shebang")
	}
	if !strings.Contains(script, `command="/usr/local/bin/pcmd"`) {
		t.Fatal("missing command directive")
	}
	if !strings.Contains(script, `command_args="--foreground -p 8767 --host 0.0.0.0"`) {
		t.Fatal("missing command_args")
	}
	if !strings.Contains(script, "supervisor=supervise-daemon") {
		t.Fatal("the service must run under supervise-daemon so it is restarted")
	}
	if strings.Contains(script, "command_background") {
		t.Fatal("supervise-daemon does not support command_background")
	}
	if !strings.Contains(script, "respawn_delay=5") || !strings.Contains(script, "respawn_max=0") {
		t.Fatal("missing respawn settings")
	}
	if !strings.Contains(script, "pidfile=") {
		t.Fatal("missing pidfile")
	}
	if !strings.Contains(script, "depend()") {
		t.Fatal("missing depend block")
	}
	if !strings.Contains(script, "need net") {
		t.Fatal("missing 'need net' in depend block")
	}
	if !strings.Contains(script, "after firewall") {
		t.Fatal("missing 'after firewall' in depend block")
	}
	if !strings.Contains(script, `name="pocketcmd"`) {
		t.Fatal("missing name")
	}
	if !strings.Contains(script, `description="PocketCmd Server"`) {
		t.Fatal("missing description")
	}
	if !strings.Contains(script, `command_user="alice"`) {
		t.Fatal("service must drop privileges to the installing user")
	}
	if !strings.Contains(script, `export HOME="/home/alice"`) {
		t.Fatal("service must run with the installing user's HOME so ~/.pocketcmd resolves")
	}
}

func TestGenerateOpenRCScript_DifferentParams(t *testing.T) {
	script := GenerateOpenRCScript("/opt/bin/server", 9999, "127.0.0.1", "bob", "/home/bob")
	if !strings.Contains(script, `command="/opt/bin/server"`) {
		t.Fatal("missing custom binary path")
	}
	if !strings.Contains(script, "-p 9999") {
		t.Fatal("missing custom port")
	}
	if !strings.Contains(script, "--host 127.0.0.1") {
		t.Fatal("missing custom host")
	}
}

func TestInstall_NoInitSystem(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("skipping on Linux where an actual init system may be present")
	}

	expectedMsg := "No supported init system found (systemd or OpenRC required)"
	p := OpenRCScriptPath()
	if p != "/etc/init.d/pocketcmd" {
		t.Fatalf("unexpected OpenRC script path: %s", p)
	}
	_ = expectedMsg
}

func TestGenerateServiceFile_MatchesPerOSGenerator(t *testing.T) {
	got, err := GenerateServiceFile("/usr/local/bin/pcmd", 8767, "0.0.0.0")
	if runtime.GOOS == "darwin" {
		if err != nil || got != GenerateLaunchdPlist("/usr/local/bin/pcmd", 8767, "0.0.0.0") {
			t.Fatalf("darwin: err=%v", err)
		}
	}
	if runtime.GOOS == "linux" && DetectInitSystem() == "systemd" {
		if err != nil || got != GenerateSystemdUnit("/usr/local/bin/pcmd", 8767, "0.0.0.0") {
			t.Fatalf("systemd: err=%v", err)
		}
	}
}

func TestServiceFileMatches(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no service file on this OS")
	}
	if runtime.GOOS == "linux" && DetectInitSystem() != "systemd" {
		t.Skip("needs the per-user systemd path")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, err := ServiceFileMatches("/bin/pcmd", 8767, "0.0.0.0"); err == nil {
		t.Fatal("a missing service file must not match")
	}
	want, err := GenerateServiceFile("/bin/pcmd", 8767, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	p := ServiceFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(want), 0644); err != nil {
		t.Fatal(err)
	}
	if ok, err := ServiceFileMatches("/bin/pcmd", 8767, "0.0.0.0"); err != nil || !ok {
		t.Fatalf("identical definition must match: ok=%v err=%v", ok, err)
	}
	if ok, _ := ServiceFileMatches("/bin/pcmd", 9000, "0.0.0.0"); ok {
		t.Fatal("a different port must not match")
	}
	if ok, _ := ServiceFileMatches("/opt/pcmd", 8767, "0.0.0.0"); ok {
		t.Fatal("a different binary path must not match")
	}
}

func TestLingerFromLoginctl(t *testing.T) {
	cases := []struct {
		out            string
		err            error
		enabled, known bool
	}{
		{"Linger=yes\n", nil, true, true},
		{"Linger=no\n", nil, false, true},
		{"garbage", nil, false, false},
		{"", os.ErrNotExist, false, false},
	}
	for _, c := range cases {
		enabled, known := lingerFromLoginctl(func() ([]byte, error) { return []byte(c.out), c.err })
		if enabled != c.enabled || known != c.known {
			t.Errorf("%q: got (%v,%v) want (%v,%v)", c.out, enabled, known, c.enabled, c.known)
		}
	}
}
