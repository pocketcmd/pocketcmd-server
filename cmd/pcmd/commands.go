package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

type statusReport struct {
	Version      string `json:"version"`
	Installed    bool   `json:"installed"`
	Running      bool   `json:"running"`
	PID          int    `json:"pid,omitempty"`
	Port         int    `json:"port"`
	Devices      int    `json:"paired_devices"`
	ServiceMode  string `json:"service_mode,omitempty"`
	ConfigPath   string `json:"config_path"`
	DataDir      string `json:"data_dir"`
	StdoutLog    string `json:"stdout_log,omitempty"`
	Linger       *bool  `json:"linger,omitempty"`
	ServiceState string `json:"service_state"`
}

func runStatus(cmd *cobra.Command, args []string) error {
	port, _, _ := runtimeSettings(cmd)
	return statusCore(cmd.OutOrStdout(), port, jsonFlag(cmd))
}

func statusCore(w io.Writer, port int, asJSON bool) error {
	r, err := gatherStatus(port)
	if err != nil {
		return err
	}
	if asJSON {
		if err := writeJSON(w, r); err != nil {
			return err
		}
	} else {
		printBanner(w)
		printStatus(w, r)
	}
	switch r.ServiceState {
	case "not_installed":
		return exitSilently(exitNotInstalled)
	case "stopped":
		return exitSilently(exitServiceStopped)
	}
	return nil
}

func gatherStatus(port int) (statusReport, error) {
	r := statusReport{Version: version, Port: port, ConfigPath: config.ConfigFilePath(), DataDir: config.PocketCmdDir()}
	status := svc.status()
	r.Installed, r.Running, r.PID = status.Installed, status.Running, status.PID
	switch {
	case !status.Installed:
		r.ServiceState = "not_installed"
	case status.Running:
		r.ServiceState = "running"
	default:
		r.ServiceState = "stopped"
	}

	db, err := stateDB()
	if err != nil {
		return r, err
	}
	devices, _ := pki.NewDeviceRegistry(db).List()
	r.Devices = countActiveDevices(devices)

	if featureCfg, err := config.LoadFeatureConfig(config.ConfigFilePath()); err == nil {
		r.ServiceMode = featureCfg.ServiceMode
	}
	logPath := filepath.Join(config.PocketCmdDir(), "server.log")
	if _, err := os.Stat(logPath); err == nil {
		r.StdoutLog = logPath
	}
	if enabled, known := svc.lingerStatus(); known {
		r.Linger = &enabled
	}
	return r, nil
}

func printStatus(w io.Writer, r statusReport) {
	switch r.ServiceState {
	case "not_installed":
		fmt.Fprintln(w, "  Status:   not installed")
		fmt.Fprintln(w, "  Run 'pcmd' to set up.")
		return
	case "running":
		fmt.Fprintf(w, "  Status:   running (pid %d)\n", r.PID)
	default:
		fmt.Fprintln(w, "  Status:   stopped (run 'pcmd start')")
	}
	fmt.Fprintf(w, "  Port:     %d\n", r.Port)
	fmt.Fprintf(w, "  Devices:  %d paired\n", r.Devices)
	if r.ServiceMode != "" {
		fmt.Fprintf(w, "  Mode:     %s\n", r.ServiceMode)
	}
	if r.Linger != nil {
		if *r.Linger {
			fmt.Fprintln(w, "  Linger:   enabled (the service survives logout)")
		} else {
			fmt.Fprintln(w, "  Linger:   disabled (the service stops at logout; run: loginctl enable-linger $USER)")
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Config:   %s\n", r.ConfigPath)
	fmt.Fprintf(w, "  Data:     %s\n", r.DataDir)
	if r.StdoutLog != "" {
		fmt.Fprintf(w, "  Stdout:   %s (structured log: pcmd logs)\n", r.StdoutLog)
	}
}

func runInstall(cmd *cobra.Command, args []string) error {
	allowUnpaired, _ := cmd.Flags().GetBool("allow-unpaired")
	port, host, _ := runtimeSettings(cmd)
	return installCore(cmd.OutOrStdout(), port, host, allowUnpaired, currentPrivileges())
}

var errInstallUnpaired = fmt.Errorf("pair a device first: run `pcmd` and scan the code, then the service is installed for you (pass --allow-unpaired to install anyway)")

func installCore(w io.Writer, port int, host string, allowUnpaired bool, pc privilegeContext) error {
	if err := checkPrivileges(pc); err != nil {
		return err
	}
	if !allowUnpaired {
		db, err := stateDB()
		if err != nil {
			return err
		}
		devices, err := pki.NewDeviceRegistry(db).List()
		if err != nil {
			return err
		}
		if len(devices) == 0 {
			return errInstallUnpaired
		}
	}
	binPath, _ := os.Executable()
	warnings, err := svc.install(binPath, port, host)
	printServiceWarnings(w, warnings)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "Service installed and started.")
	return nil
}

func runUninstall(cmd *cobra.Command, args []string) error {
	yes, nonInteractive := guardFlags(cmd)
	return uninstallCore(cmd.OutOrStdout(), yes, nonInteractive)
}

func uninstallCore(w io.Writer, yes, nonInteractive bool) error {
	if !svc.isInstalled() {
		fmt.Fprintln(w, "PocketCmd is not installed as a service.")
		return nil
	}

	ok, err := confirmDestructive(w, "remove the service", "Stop and remove the PocketCmd service?", yes, nonInteractive)
	if err != nil || !ok {
		return err
	}

	if err := svc.uninstall(); err != nil {
		return err
	}
	fmt.Fprintln(w, "Service stopped and removed.")
	return nil
}

func runListDevices(cmd *cobra.Command, args []string) error {
	all, _ := cmd.Flags().GetBool("all")
	return listDevicesCore(cmd.OutOrStdout(), jsonFlag(cmd), all)
}

type deviceRow struct {
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	UserID      string `json:"user_id,omitempty"`
	UserName    string `json:"user_name,omitempty"`
	DeviceName  string `json:"device_name"`
	DeviceLabel string `json:"device_label,omitempty"`
	Status      string `json:"status"`
	PairedAt    string `json:"paired_at"`
	RemovedAt   string `json:"removed_at,omitempty"`
	LastSeenAt  string `json:"last_seen_at,omitempty"`
}

func listDevicesCore(w io.Writer, asJSON, all bool) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	registry := pki.NewDeviceRegistry(db)
	devices, err := registry.List()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	rows := make([]deviceRow, 0, len(devices))
	for _, d := range devices {
		if !all && d.Status != pki.DeviceStatusActive {
			continue
		}
		fp, _ := pki.PubKeyFingerprint(d.PublicKey)
		row := deviceRow{DeviceID: d.DeviceID, Fingerprint: fp, UserID: d.UserID, DeviceName: d.DeviceName,
			DeviceLabel: d.DeviceLabel, Status: d.Status, PairedAt: d.PairedAt, LastSeenAt: d.LastSeenAt}
		if d.Status != pki.DeviceStatusActive {
			row.RemovedAt = d.RevokedAt
		}
		if d.UserID != "" {
			if u, _ := users.FindByID(d.UserID); u != nil {
				row.UserName = u.DisplayName
			}
		}
		rows = append(rows, row)
	}
	if asJSON {
		return writeJSON(w, rows)
	}
	if len(rows) == 0 {
		if all {
			fmt.Fprintln(w, "No devices.")
		} else {
			fmt.Fprintln(w, "No active devices.")
		}
		return nil
	}
	if all {
		fmt.Fprintf(w, "%-15s  %-20s  %-30s  %-8s  %-20s  %s\n", "FINGERPRINT", "USER", "DEVICE", "STATUS", "PAIRED", "REMOVED")
	} else {
		fmt.Fprintf(w, "%-15s  %-20s  %-30s  %-8s  %s\n", "FINGERPRINT", "USER", "DEVICE", "STATUS", "PAIRED")
	}
	for _, r := range rows {
		userName := r.UserName
		if userName == "" {
			userName = "-"
		}
		if all {
			fmt.Fprintf(w, "%-15s  %-20s  %-30s  %-8s  %-20s  %s\n",
				shortFP(r.Fingerprint), userName, r.DeviceName, r.Status, r.PairedAt, orDefault(r.RemovedAt, "", "-"))
		} else {
			fmt.Fprintf(w, "%-15s  %-20s  %-30s  %-8s  %s\n",
				shortFP(r.Fingerprint), userName, r.DeviceName, r.Status, r.PairedAt)
		}
	}
	return nil
}

func runRevokeDevice(cmd *cobra.Command, args []string) error {
	yes, nonInteractive := guardFlags(cmd)
	return revokeDeviceCore(cmd.OutOrStdout(), args, yes, nonInteractive)
}

func revokeDeviceCore(w io.Writer, args []string, yes, nonInteractive bool) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	registry := pki.NewDeviceRegistry(db)

	if len(args) == 1 {
		dev, err := registry.FindByPubKeyPrefix(args[0])
		if err != nil {
			return err
		}
		ok, err := confirmDestructive(w, "revoke the device",
			fmt.Sprintf("Revoke device %s (%s)? It can never pair again with this key.", dev.DeviceName, dev.DeviceID),
			yes, nonInteractive)
		if err != nil || !ok {
			return err
		}
		// Soft-revoke rather than delete: the revoked key must not silently re-pair (registration is idempotent on an existing record).
		if err := registry.Revoke(dev.DeviceID); err != nil {
			return err
		}
		fmt.Fprintf(w, "Revoked device: %s (%s)\n", dev.DeviceName, dev.DeviceID)
		printCLIRevokeCaveat(w)
		return nil
	}

	// Check the empty registry before any interactivity gating so the empty case behaves the same under TTY, pipe or --non-interactive.
	devices, err := registry.List()
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		fmt.Fprintln(w, "No paired devices.")
		return nil
	}

	if !isInteractive(nonInteractive) {
		return fmt.Errorf("revoke-device needs a fingerprint argument without an interactive terminal (see `pcmd list-devices`)")
	}

	labels := make([]string, 0, len(devices)+1)
	for _, d := range devices {
		fp, _ := pki.PubKeyFingerprint(d.PublicKey)
		labels = append(labels, fmt.Sprintf("%s (%s) fingerprint %s", d.DeviceName, d.DeviceID, shortFP(fp)))
	}
	labels = append(labels, "(cancel)")

	idx, err := promptSelect("Revoke which device?", labels)
	if err != nil && !errors.Is(err, errPromptAborted) {
		return err
	}
	if err != nil || idx == len(devices) {
		fmt.Fprintln(w, "Cancelled.")
		return nil
	}

	dev := devices[idx]
	ok, err := confirmDestructive(w, "revoke the device",
		fmt.Sprintf("Revoke device %s (%s)? It can never pair again with this key.", dev.DeviceName, dev.DeviceID),
		yes, nonInteractive)
	if err != nil || !ok {
		return err
	}

	if err := registry.Revoke(dev.DeviceID); err != nil {
		return err
	}
	fmt.Fprintf(w, "Revoked device: %s (%s)\n", dev.DeviceName, dev.DeviceID)
	printCLIRevokeCaveat(w)
	return nil
}

func printCLIRevokeCaveat(w io.Writer) {
	fmt.Fprintln(w, "Note: mTLS access is cut immediately. Removing the device from the")
	fmt.Fprintln(w, "      app instead also publishes a signed, permanent revocation that")
	fmt.Fprintln(w, "      stops other devices from re-sharing vault keys with it. Prefer")
	fmt.Fprintln(w, "      in-app removal when the device held vault access.")
}

func pickFreePort(host string) (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func runSync(cmd *cobra.Command, args []string) error {
	w := cmd.OutOrStdout()
	flags := cmd.Flags()
	_, host, advertiseIP := runtimeSettings(cmd)
	debugLog, _ := flags.GetString("debug-log")
	timeout, _ := flags.GetDuration("timeout")

	// The export is audited into the real audit log even though the state dir below is throwaway.
	auditLogOverride = filepath.Join(config.PocketCmdDir(), "audit.log")
	defer func() { auditLogOverride = "" }()

	// A throwaway state dir keeps the one-shot pairing from creating durable users or devices in ~/.pocketcmd.
	tmpDir, err := os.MkdirTemp("", "pcmd-ssh-sync-*")
	if err != nil {
		return fmt.Errorf("temp state dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	config.SetPocketCmdDir(tmpDir)

	// A random port keeps the one-shot server off the standing server's port.
	effectivePort := 0
	if flags.Changed("port") {
		effectivePort, _ = flags.GetInt("port")
	} else {
		effectivePort, err = pickFreePort(host)
		if err != nil {
			return fmt.Errorf("pick free port: %w", err)
		}
	}

	lanIP := resolveAdvertiseIP(advertiseIP, host)

	rs, err := startFullServer(
		effectivePort, host, debugLog, advertiseIP,
		false,
	)
	if err != nil {
		return err
	}
	defer rs.cancel()

	// The long-running server never registers this route.
	rs.srv.RegisterSSHRoutes()
	rs.srv.EnableSSHOneShot()
	done := make(chan string, 1)
	rs.srv.OnSSHConfigsFetch(func(deviceID string) {
		select {
		case done <- deviceID:
		default:
		}
	})

	fmt.Fprintf(w, "One-shot SSH sync listening on %s (timeout %s)\n", httpsURL(lanIP, effectivePort), timeout)

	token := rs.pairHandler.GeneratePairingToken()
	pairingURL := syncURL(lanIP, effectivePort, token, rs.serverFP)
	fmt.Fprintln(w, "Scan QR to sync SSH configs:")
	fmt.Fprintln(w)
	printPairingQR(w, pairingURL)

	fmt.Fprintln(w, "Waiting for device to fetch SSH configs...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case deviceID := <-done:
		if deviceID != "" {
			fmt.Fprintf(w, "SSH configs fetched by device %s. Exiting.\n", deviceID)
		} else {
			fmt.Fprintln(w, "SSH configs fetched. Exiting.")
		}
		return nil
	case <-sigCh:
		fmt.Fprintln(w, "\nCancelled.")
		return errInterrupted
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for device to fetch SSH configs")
	}
}

func runRotateServerCert(cmd *cobra.Command, args []string) error {
	w := cmd.OutOrStdout()
	port, host, advertiseIP := runtimeSettings(cmd)
	yes, nonInteractive := guardFlags(cmd)

	ok, err := confirmDestructive(w, "rotate the server certificate",
		"Rotate the server certificate? Every paired device must scan the new code before it can connect again.",
		yes, nonInteractive)
	if err != nil || !ok {
		return err
	}

	tlsDir := config.TLSDir()
	// A failed delete must abort, or LoadOrGenerateServerCert reloads the old pair and reports it as rotated.
	for _, name := range []string{"server.crt", "server.key"} {
		if err := os.Remove(filepath.Join(tlsDir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old %s: %w", name, err)
		}
	}
	_, fp, err := pki.LoadOrGenerateServerCert(tlsDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Server certificate rotated. New fingerprint: %s\n", shortFP(fp))

	// A running server keeps serving the certificate it loaded at start.
	var restartErr error
	if svc.isInstalled() {
		restartErr = restartService(w, port, host)
	} else {
		fmt.Fprintln(w, "If the server is running in the foreground, stop it with Ctrl+C and start it again with 'pcmd' so it serves the new certificate.")
	}

	// Known active devices re-pair through the CSR-signature fast path without a token; the token here only fills the URL format.
	repairURL := pairURL(resolveAdvertiseIP(advertiseIP, host), port, randomToken(), fp)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scan this code in the app on every paired device to re-pair it:")
	fmt.Fprintln(w)
	printPairingQR(w, repairURL)
	return restartErr
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

func countActiveDevices(devices []pki.DeviceRecord) int {
	n := 0
	for _, d := range devices {
		if d.Status == pki.DeviceStatusActive {
			n++
		}
	}
	return n
}

func printServiceWarnings(w io.Writer, warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(w, "  Warning: %s\n", warning)
	}
}
