// Package service installs and controls the pcmd daemon under systemd, OpenRC or launchd.
package service

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	SystemdLabel    = "pocketcmd"
	LaunchdLabel    = "com.pocketcmd.server"
	OpenRCName      = "pocketcmd"
	OpenRCScriptDir = "/etc/init.d"
)

type ServiceStatus struct {
	Installed bool
	Running   bool
	PID       int
}

func DetectOS() string {
	return runtime.GOOS
}

func DetectInitSystem() string {
	if _, err := exec.LookPath("systemctl"); err == nil {
		return "systemd"
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	return "none"
}

func OpenRCScriptPath() string {
	return filepath.Join(OpenRCScriptDir, OpenRCName)
}

func SystemdUnitPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", "pocketcmd.service")
}

func LaunchdPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", "com.pocketcmd.server.plist")
}

func ServiceFilePath() string {
	switch DetectOS() {
	case "linux":
		if DetectInitSystem() == "openrc" {
			return OpenRCScriptPath()
		}
		return SystemdUnitPath()
	case "darwin":
		return LaunchdPlistPath()
	default:
		return ""
	}
}

func GenerateSystemdUnit(binPath string, port int, host string) string {
	return fmt.Sprintf(`[Unit]
Description=PocketCmd Server
After=network.target

[Service]
ExecStart=%s --foreground -p %d --host %s
Restart=always
RestartSec=5

# --- Sandboxing (least privilege) ---
# Whole filesystem read-only except the state dir; ~/.ssh stays readable but
# not writable. Adjust ReadWritePaths if you relocate the state directory.
ProtectSystem=strict
ReadWritePaths=%%h/.pocketcmd
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true

[Install]
WantedBy=default.target
`, binPath, port, host)
}

func GenerateOpenRCScript(binaryPath string, port int, host, runAs, home string) string {
	return fmt.Sprintf(`#!/sbin/openrc-run

name="pocketcmd"
description="PocketCmd Server"
command="%s"
command_args="--foreground -p %d --host %s"
command_user="%s"
directory="%s"
export HOME="%s"
supervisor=supervise-daemon
respawn_delay=5
respawn_max=0
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/pocketcmd.log"
error_log="/var/log/pocketcmd.log"

depend() {
    need net
    after firewall
}
`, binaryPath, port, host, runAs, home, home)
}

func serviceUser() (name, home string, err error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		u, err := user.Lookup(sudoUser)
		if err != nil {
			return "", "", fmt.Errorf("resolve SUDO_USER %q: %w", sudoUser, err)
		}
		return u.Username, u.HomeDir, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("resolve current user: %w", err)
	}
	home = u.HomeDir
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		home = h
	}
	return u.Username, home, nil
}

func GenerateLaunchdPlist(binPath string, port int, host string) string {
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".pocketcmd", "server.log")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--foreground</string>
        <string>-p</string>
        <string>%d</string>
        <string>--host</string>
        <string>%s</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
</dict>
</plist>
`, LaunchdLabel, binPath, port, host, logPath, logPath)
}

func IsInstalled() bool {
	p := ServiceFilePath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func Install(binaryPath string, port int, host string) ([]string, error) {
	warnings, err := WriteServiceFile(binaryPath, port, host)
	if err != nil {
		return warnings, err
	}
	return warnings, Start()
}

func WriteServiceFile(binaryPath string, port int, host string) ([]string, error) {
	var warnings []string
	if strings.HasPrefix(binaryPath, "/tmp/") || strings.HasPrefix(binaryPath, "/var/folders/") {
		warnings = append(warnings, fmt.Sprintf("binary path %s looks temporary; the service may break after reboot", binaryPath))
	}

	var more []string
	var err error
	switch DetectOS() {
	case "linux":
		switch DetectInitSystem() {
		case "systemd":
			more, err = writeSystemd(binaryPath, port, host)
		case "openrc":
			more, err = writeOpenRC(binaryPath, port, host)
		default:
			err = fmt.Errorf("no supported init system found (systemd or OpenRC required); run with --foreground and manage the process yourself (e.g., nohup, screen, tmux, supervisord)")
		}
	case "darwin":
		err = writeLaunchd(binaryPath, port, host)
	default:
		err = fmt.Errorf("unsupported OS: %s", DetectOS())
	}
	return append(warnings, more...), err
}

func GenerateServiceFile(binaryPath string, port int, host string) (string, error) {
	switch DetectOS() {
	case "linux":
		switch DetectInitSystem() {
		case "systemd":
			return GenerateSystemdUnit(binaryPath, port, host), nil
		case "openrc":
			runAs, home, err := serviceUser()
			if err != nil {
				return "", err
			}
			return GenerateOpenRCScript(binaryPath, port, host, runAs, home), nil
		default:
			return "", fmt.Errorf("no supported init system found")
		}
	case "darwin":
		return GenerateLaunchdPlist(binaryPath, port, host), nil
	default:
		return "", fmt.Errorf("unsupported OS: %s", DetectOS())
	}
}

func ServiceFileMatches(binaryPath string, port int, host string) (bool, error) {
	want, err := GenerateServiceFile(binaryPath, port, host)
	if err != nil {
		return false, err
	}
	have, err := os.ReadFile(ServiceFilePath())
	if err != nil {
		return false, err
	}
	return string(have) == want, nil
}

func Start() error {
	switch DetectOS() {
	case "linux":
		switch DetectInitSystem() {
		case "systemd":
			if err := exec.Command("systemctl", "--user", "start", SystemdLabel).Run(); err != nil {
				return fmt.Errorf("start: %w", err)
			}
			return nil
		case "openrc":
			if err := exec.Command("rc-service", OpenRCName, "start").Run(); err != nil {
				return fmt.Errorf("rc-service start: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("no supported init system found")
		}
	case "darwin":
		if err := exec.Command("launchctl", "load", LaunchdPlistPath()).Run(); err != nil {
			return fmt.Errorf("launchctl load: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS: %s", DetectOS())
	}
}

func Stop() error {
	switch DetectOS() {
	case "linux":
		switch DetectInitSystem() {
		case "systemd":
			if err := exec.Command("systemctl", "--user", "stop", SystemdLabel).Run(); err != nil {
				return fmt.Errorf("stop: %w", err)
			}
			return nil
		case "openrc":
			if err := exec.Command("rc-service", OpenRCName, "stop").Run(); err != nil {
				return fmt.Errorf("rc-service stop: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("no supported init system found")
		}
	case "darwin":
		if err := exec.Command("launchctl", "unload", LaunchdPlistPath()).Run(); err != nil {
			return fmt.Errorf("launchctl unload: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS: %s", DetectOS())
	}
}

func LingerStatus() (enabled, known bool) {
	if DetectOS() != "linux" || DetectInitSystem() != "systemd" {
		return false, false
	}
	return lingerFromLoginctl(exec.Command("loginctl", "show-user", currentUserName(), "--property=Linger").Output)
}

func lingerFromLoginctl(run func() ([]byte, error)) (enabled, known bool) {
	out, err := run()
	if err != nil {
		return false, false
	}
	switch strings.TrimSpace(string(out)) {
	case "Linger=yes":
		return true, true
	case "Linger=no":
		return false, true
	}
	return false, false
}

func currentUserName() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func writeSystemd(binPath string, port int, host string) ([]string, error) {
	var warnings []string
	unitPath := SystemdUnitPath()
	if err := os.MkdirAll(filepath.Dir(unitPath), 0755); err != nil {
		return nil, fmt.Errorf("create systemd dir: %w", err)
	}

	unit := GenerateSystemdUnit(binPath, port, host)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return nil, fmt.Errorf("write unit file: %w", err)
	}

	if enabled, known := LingerStatus(); known && !enabled {
		warnings = append(warnings, fmt.Sprintf("loginctl enable-linger is not set, so the service may not persist after logout; run: loginctl enable-linger %s", currentUserName()))
	}

	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return nil, fmt.Errorf("daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "--user", "enable", SystemdLabel).Run(); err != nil {
		return nil, fmt.Errorf("enable: %w", err)
	}
	return warnings, nil
}

func writeOpenRC(binPath string, port int, host string) ([]string, error) {
	var warnings []string
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("installing the OpenRC service writes %s and needs root: rerun with sudo (the service itself runs as your user)", OpenRCScriptPath())
	}
	runAs, home, err := serviceUser()
	if err != nil {
		return nil, err
	}
	if runAs == "root" {
		warnings = append(warnings, "installing as root; the service and its metric commands will run as root with state in /root/.pocketcmd. Prefer 'sudo pcmd install' from a normal user account")
	}
	scriptPath := OpenRCScriptPath()
	script := GenerateOpenRCScript(binPath, port, host, runAs, home)
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return nil, fmt.Errorf("write OpenRC script: %w", err)
	}
	if err := exec.Command("rc-update", "add", OpenRCName, "default").Run(); err != nil {
		return nil, fmt.Errorf("rc-update add: %w", err)
	}
	return warnings, nil
}

func writeLaunchd(binPath string, port int, host string) error {
	plistPath := LaunchdPlistPath()
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}

	plist := GenerateLaunchdPlist(binPath, port, host)
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	return nil
}

func Uninstall() error {
	switch DetectOS() {
	case "linux":
		initSys := DetectInitSystem()
		if initSys == "openrc" {
			_ = exec.Command("rc-service", OpenRCName, "stop").Run()
			_ = exec.Command("rc-update", "del", OpenRCName, "default").Run()
			_ = os.Remove(OpenRCScriptPath())
		} else {
			_ = exec.Command("systemctl", "--user", "stop", SystemdLabel).Run()
			_ = exec.Command("systemctl", "--user", "disable", SystemdLabel).Run()
			_ = os.Remove(SystemdUnitPath())
			_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		}
	case "darwin":
		plistPath := LaunchdPlistPath()
		_ = exec.Command("launchctl", "unload", plistPath).Run()
		_ = os.Remove(plistPath)
	}
	return nil
}

func GetStatus() ServiceStatus {
	switch DetectOS() {
	case "linux":
		initSys := DetectInitSystem()
		if initSys == "openrc" {
			return getOpenRCStatus()
		}
		return getSystemdStatus()
	case "darwin":
		return getLaunchdStatus()
	}
	return ServiceStatus{}
}

func getSystemdStatus() ServiceStatus {
	status := ServiceStatus{}
	if _, err := os.Stat(SystemdUnitPath()); err != nil {
		return status
	}
	status.Installed = true

	out, err := exec.Command("systemctl", "--user", "is-active", SystemdLabel).Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		status.Running = true
	}

	pidOut, err := exec.Command("systemctl", "--user", "show", SystemdLabel, "--property=MainPID").Output()
	if err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(pidOut)), "=", 2)
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &status.PID)
		}
	}
	return status
}

func getOpenRCStatus() ServiceStatus {
	status := ServiceStatus{}
	if _, err := os.Stat(OpenRCScriptPath()); err != nil {
		return status
	}
	status.Installed = true

	out, err := exec.Command("rc-service", OpenRCName, "status").Output()
	if err == nil && strings.Contains(string(out), "started") {
		status.Running = true
	}

	pidData, err := os.ReadFile(fmt.Sprintf("/run/%s.pid", OpenRCName))
	if err == nil {
		fmt.Sscanf(strings.TrimSpace(string(pidData)), "%d", &status.PID)
	}
	return status
}

func getLaunchdStatus() ServiceStatus {
	status := ServiceStatus{}
	if _, err := os.Stat(LaunchdPlistPath()); err != nil {
		return status
	}
	status.Installed = true

	out, err := exec.Command("launchctl", "list", LaunchdLabel).Output()
	if err == nil && len(out) > 0 {
		status.Running = true
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "PID") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					fmt.Sscanf(parts[2], "%d", &status.PID)
				}
			}
		}
	}
	return status
}

func probeHost(host string) string {
	h := strings.Trim(host, "[]")
	ip := net.ParseIP(h)
	switch {
	case h == "", ip != nil && ip.IsUnspecified() && ip.To4() != nil:
		return "127.0.0.1"
	case ip != nil && ip.IsUnspecified():
		return "::1"
	}
	return h
}

func HealthCheck(host string, port int) error {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	addr := net.JoinHostPort(probeHost(host), strconv.Itoa(port))
	resp, err := client.Get("https://" + addr + "/api/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	return nil
}

func WaitHealthy(host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := HealthCheck(host, port)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}
