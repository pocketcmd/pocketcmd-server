package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pair"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/push"
	"github.com/pocketcmd/pocketcmd-server/internal/server"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
)

var (
	version = "1.0.0-dev"
	commit  = "none"
	date    = "unknown"
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "pcmd",
		Short: "Self-hosted monitoring, encrypted sync, and team vaults for the PocketCmd app",
		Long: `PocketCmd server: run it on a machine you own, scan the QR code with the PocketCmd app,
and get server metrics, end-to-end encrypted sync, and team vault sharing on your phone.

The first run starts the server, shows a pairing QR code, waits for the owner device
to pair and then installs the background service. Later runs start the service when
it is not running and print its status; with --foreground they serve until Ctrl+C.`,
		Example: `  pcmd                              # first run: pair the owner device, install the service
  pcmd --port 9000 --host 10.8.0.1   # listen on a VPN interface instead of every address
  pcmd --non-interactive --no-qr     # headless: print the pairing URL, wait up to 5 minutes
  pcmd --foreground --debug-log /tmp/pocketcmd.log`,
		Version: fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		RunE:    runFirstRun,
		// Print runtime errors without the full usage text.
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			pf := cmd.Root().PersistentFlags()
			qrOpts.disabled, _ = pf.GetBool("no-qr")
			qrOpts.invert, _ = pf.GetBool("qr-invert")
			return validateAddressFlags(cmd.Flags())
		},
	}
	rootCmd.SetVersionTemplate("pcmd {{.Version}}\n")

	f := rootCmd.PersistentFlags()
	f.IntP("port", "p", 8767, "Server listen port")
	f.String("host", "", "Bind address: an IP address of this machine (default: the interface picked on the first run; 0.0.0.0 or :: for every interface)")
	f.Bool("no-qr", false, "Never draw QR codes; print the URL only")
	f.Bool("qr-invert", false, "Swap dark and light QR modules (for a dark terminal without colour support)")

	rootCmd.Flags().Bool("foreground", false, "Run in foreground, don't install service")
	rootCmd.Flags().Duration("pair-timeout", firstRunPairingTimeout, "How long the first run waits for a device to pair (0 = forever)")
	addDebugLogFlag(rootCmd)
	addAdvertiseIPFlag(rootCmd)
	addNonInteractiveFlag(rootCmd)

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show service status, paired devices, port",
		Long: `Show whether the background service is installed and running, the port, the number of
paired devices, the service mode and the data paths. On Linux it also reports whether
loginctl lingering is enabled for the user (without it the service stops at logout).

Exit codes: 0 running, 2 installed but stopped, 3 not installed.`,
		Example: `  pcmd status
  pcmd status --json | jq .paired_devices`,
		Args: cobra.NoArgs,
		RunE: runStatus,
	}
	addJSONFlag(statusCmd)
	rootCmd.AddCommand(statusCmd)

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as background service",
		Long: `Write the service definition (a systemd user unit, an OpenRC script or a launchd agent),
register it with the init system and start it. The first run does this for you once
a device has paired; use it by hand after an uninstall or on a restored data directory.

On a host where no device has paired yet the command refuses: the unit would start
a server nobody can reach. Pass --allow-unpaired to install anyway.`,
		Example: `  pcmd install
  pcmd install --port 9000`,
		Args: cobra.NoArgs,
		RunE: runInstall,
	}
	installCmd.Flags().Bool("allow-unpaired", false, "Install even though no device has paired yet")
	rootCmd.AddCommand(installCmd)

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove background service",
		Long: `Stop the background service and remove its definition from the init system. The data
directory (~/.pocketcmd: devices, certificates, sync data) is left in place.`,
		Example: `  pcmd uninstall
  pcmd uninstall --yes`,
		Args: cobra.NoArgs,
		RunE: runUninstall,
	}
	addYesFlag(uninstallCmd)
	rootCmd.AddCommand(uninstallCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:     "start",
		Short:   "Start the installed background service",
		Long:    `Start the background service that 'pcmd stop' stopped and wait for it to answer /api/health.`,
		Example: `  pcmd start`,
		Args:    cobra.NoArgs,
		RunE:    runStart,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "stop",
		Short: "Stop the background service (keeps it installed)",
		Long: `Stop the background service. The service stays installed, so it comes back with
'pcmd start' or the next plain 'pcmd'. Use this before 'pcmd restore'.`,
		Example: `  pcmd stop`,
		Args:    cobra.NoArgs,
		RunE:    runStop,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "restart",
		Short: "Restart the background service",
		Long: `Stop and start the background service. The service definition is rewritten only when
it no longer matches this binary, port and bind address (for example after the binary
moved or --port changed); otherwise the registered unit is kept as it is.`,
		Example: `  pcmd restart
  pcmd restart --port 9000   # also rewrites the unit for the new port`,
		Args: cobra.NoArgs,
		RunE: runRestart,
	})

	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the server's structured log",
		Long: `Print the newest entries of the server's structured log, oldest first. These are the same
entries the app's log screen (GET /api/logs) shows, kept in ~/.pocketcmd/state.db. The
process's own stdout/stderr (crash output) is not in it: on systemd see
'journalctl --user -u pocketcmd', on macOS ~/.pocketcmd/server.log.

--follow polls for new entries until Ctrl+C. --file reads a --debug-log file instead.`,
		Example: `  pcmd logs
  pcmd logs -f --level warn
  pcmd logs --since 2h --json
  pcmd logs --file /tmp/pocketcmd.log -f`,
		Args: cobra.NoArgs,
		RunE: runLogs,
	}
	addLogFlags(logsCmd)
	logsCmd.Flags().String("level", "", "Only show entries at this level or above (debug|info|warn|error)")
	logsCmd.Flags().String("file", "", "Read a --debug-log file instead of the log store")
	rootCmd.AddCommand(logsCmd)

	listDevicesCmd := &cobra.Command{
		Use:   "list-devices",
		Short: "List paired devices with public key fingerprints",
		Long: `List the active paired devices: public key fingerprint (truncated), owning user, device
name, status and pairing time. --all also lists removed devices with the time they were
removed: revoked (removed for good) or left (the device unpaired itself and may re-join
with a new invite).`,
		Example: `  pcmd list-devices
  pcmd list-devices --all
  pcmd list-devices --json`,
		Args: cobra.NoArgs,
		RunE: runListDevices,
	}
	addJSONFlag(listDevicesCmd)
	listDevicesCmd.Flags().Bool("all", false, "Also list revoked and left devices")
	rootCmd.AddCommand(listDevicesCmd)

	revokeDeviceCmd := &cobra.Command{
		Use:   "revoke-device [pubkey-fp]",
		Short: "Revoke a paired device by public key fingerprint prefix (interactive picker if no arg)",
		Long: `Revoke a paired device. The argument is a prefix (8+ characters) of the device's public
key fingerprint or device ID as shown by 'pcmd list-devices'; without it an
interactive picker lists the devices. Revocation is immediate (certificate renewal
fails and every request re-checks the registry) and permanent for that device key.`,
		Example: `  pcmd revoke-device a1b2c3d4
  pcmd revoke-device a1b2c3d4 --yes
  pcmd revoke-device            # pick from a list`,
		Args: cobra.MaximumNArgs(1),
		RunE: runRevokeDevice,
	}
	addYesFlag(revokeDeviceCmd)
	rootCmd.AddCommand(revokeDeviceCmd)
	rootCmd.AddCommand(newRenameDeviceCmd())

	rotateCmd := &cobra.Command{
		Use:   "rotate-server-cert",
		Short: "Regenerate server certificate (all devices must re-pair)",
		Long: `Replace the server's TLS certificate. Every paired device pinned the old fingerprint, so
each has to scan the QR code this command prints before it can connect again. The
installed service is restarted on the new certificate.`,
		Example: `  pcmd rotate-server-cert
  pcmd rotate-server-cert --yes --no-qr`,
		Args: cobra.NoArgs,
		RunE: runRotateServerCert,
	}
	addYesFlag(rotateCmd)
	addAdvertiseIPFlag(rotateCmd)
	rootCmd.AddCommand(rotateCmd)

	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "One-shot SSH config sync: print a one-time QR, exit after first fetch",
		Long: `Start a short-lived server on a random free port and print a one-time QR code. Scanning
it enrols the device (if new) and pulls the hosts from ~/.ssh/config once; the command
exits after the first successful fetch. Nothing is persisted on the server side and the
standing service is not touched.`,
		Example: `  pcmd sync
  pcmd sync --timeout 2m --advertise-ip 10.0.0.5`,
		Args: cobra.NoArgs,
		RunE: runSync,
	}
	syncCmd.Flags().Duration("timeout", 60*time.Second, "Max time to wait for a device to fetch")
	addDebugLogFlag(syncCmd)
	addAdvertiseIPFlag(syncCmd)
	rootCmd.AddCommand(syncCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "backup [output-path]",
		Short: "Backup server config, certs, and data",
		Long: `Write a tar.gz of ~/.pocketcmd (config, certificates, state.db, metrics.db, audit log).
The SQLite databases are snapshotted consistently, so the server may keep running. The
archive holds the server key and device registry and is created owner-only (0600).`,
		Example: `  pcmd backup
  pcmd backup ~/backups/pcmd.tar.gz`,
		Args: cobra.MaximumNArgs(1),
		RunE: runBackup,
	})

	restoreCmd := &cobra.Command{
		Use:   "restore <backup-path>",
		Short: "Restore from a backup archive",
		Long: `Replace ~/.pocketcmd with the contents of a backup archive. The archive is validated first
(it must contain state.db and tls/server.key and nothing outside the data directory),
then the command refuses while the service or a foreground server is running, then it
asks before overwriting an existing data directory.`,
		Example: `  pcmd stop
  pcmd restore ~/backups/pcmd.tar.gz
  pcmd start`,
		Args: cobra.ExactArgs(1),
		RunE: runRestore,
	}
	addYesFlag(restoreCmd)
	restoreCmd.Flags().Bool("force", false, "Alias of --yes: overwrite an existing ~/.pocketcmd without prompting")
	rootCmd.AddCommand(restoreCmd)

	rootCmd.AddCommand(newInviteCmd())
	rootCmd.AddCommand(newInvitesCmd())
	rootCmd.AddCommand(newRevokeInviteCmd())
	rootCmd.AddCommand(newListUsersCmd())
	rootCmd.AddCommand(newRevokeUserCmd())
	rootCmd.AddCommand(newPromoteCmd())
	rootCmd.AddCommand(newDemoteCmd())
	rootCmd.AddCommand(newRenameUserCmd())
	rootCmd.AddCommand(newTransferOwnershipCmd())
	rootCmd.AddCommand(newGrantCmd())
	rootCmd.AddCommand(newRevokePermissionCmd())
	rootCmd.AddCommand(newVaultsCmd())
	rootCmd.AddCommand(newVaultMembersCmd())
	rootCmd.AddCommand(newRequestsCmd())

	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newAuditCmd())

	return rootCmd
}

func main() {
	if err := checkHome(os.UserHomeDir); err != nil {
		fatal(err.Error())
	}
	root := newRootCmd()
	// reportExit prints errors itself so exit-code errors can stay silent.
	root.SilenceErrors = true
	err := root.Execute()
	os.Exit(reportExit(os.Stderr, err))
}

func setupLogging(debugLog string, sink server.LogSink) (logger *slog.Logger, cleanup func()) {
	store := server.NewBufferHandler(sink)
	if debugLog != "" {
		rw, err := config.NewRotatingWriter(debugLog)
		if err != nil {
			return slog.New(store), func() {}
		}
		return slog.New(server.NewTeeHandler(store, slog.NewJSONHandler(rw, nil))),
			func() { rw.Close() }
	}
	return slog.New(store), func() {}
}

func setupAuditLogger() (*slog.Logger, func()) {
	auditPath := auditLogOverride
	if auditPath == "" {
		auditPath = filepath.Join(config.PocketCmdDir(), "audit.log")
	}
	os.MkdirAll(filepath.Dir(auditPath), 0700)
	rw, err := config.NewRotatingWriter(auditPath)
	if err != nil {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil)), func() {}
	}
	return slog.New(slog.NewJSONHandler(rw, nil)), func() { rw.Close() }
}

func getAllLANIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{"127.0.0.1"}
	}
	return lanIPsFrom(addrs)
}

// Set by the one-shot sync so its SSH export lands in the real audit log despite the throwaway state dir.
var auditLogOverride string

func defaultBindHost() string {
	return getAllLANIPs()[0]
}

func resolveAdvertiseIP(advertiseIP, host string) string {
	if advertiseIP != "" {
		return advertiseIP
	}
	if ip := specificBindIP(host); ip != "" {
		return ip
	}
	return getAllLANIPs()[0]
}

func reachableIPs(host string) []string {
	if ip := specificBindIP(host); ip != "" {
		return []string{ip}
	}
	return getAllLANIPs()
}

func runtimeSettings(cmd *cobra.Command) (port int, host, advertiseIP string) {
	flags := cmd.Flags()
	port, _ = flags.GetInt("port")
	host, _ = flags.GetString("host")
	advertiseIP, _ = flags.GetString("advertise-ip")
	if cfg, err := config.LoadFeatureConfig(config.ConfigFilePath()); err == nil {
		if !flags.Changed("port") && cfg.Port != 0 {
			port = cfg.Port
		}
		if !flags.Changed("host") && cfg.Host != "" {
			host = cfg.Host
		}
		if !flags.Changed("advertise-ip") && cfg.AdvertiseIP != "" {
			advertiseIP = cfg.AdvertiseIP
		}
	}
	if host == "" {
		host = defaultBindHost()
	}
	return port, host, advertiseIP
}

type runningServer struct {
	srv         *server.Server
	pairHandler *pair.PairingHandler
	serverFP    string
	ctx         context.Context
	cancel      context.CancelFunc
}

func openStateAndLogging(debugLog string) (db *sql.DB, logStore *server.LogStore, logger *slog.Logger, cleanup func(), err error) {
	db, err = stateDB()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	logStore = server.NewLogStore(db, 10000)

	logger, cleanup = setupLogging(debugLog, logStore)
	slog.SetDefault(logger)
	return db, logStore, logger, cleanup, nil
}

func loadServerIdentity(db *sql.DB, logger *slog.Logger) (tls.Certificate, string, *ecdsa.PrivateKey, error) {
	willGenerate := !pki.ServerCertExists(config.TLSDir())
	serverCert, serverFP, err := pki.LoadOrGenerateServerCert(config.TLSDir())
	if err != nil {
		return tls.Certificate{}, "", nil, fmt.Errorf("TLS setup: %w", err)
	}
	if willGenerate {
		devices, _ := pki.NewDeviceRegistry(db).List()
		if len(devices) > 0 {
			logger.Warn(
				"server cert was regenerated; paired devices must re-pair",
				"paired_devices", len(devices),
				"new_fingerprint", serverFP,
			)
			fmt.Fprintln(os.Stderr,
				"⚠  pcmd: server TLS cert was regenerated. "+
					"All paired devices must re-pair: their stored fingerprint "+
					"no longer matches the server's.",
			)
		}
	}

	serverKey, err := pki.LoadServerKey(config.TLSDir())
	if err != nil {
		return tls.Certificate{}, "", nil, fmt.Errorf("load server key: %w", err)
	}
	return serverCert, serverFP, serverKey, nil
}

func startFullServer(port int, host, debugLog, advertiseIP string, withServices bool) (*runningServer, error) {
	// An empty host would bind every interface; that is opt-in through --host 0.0.0.0.
	if host == "" {
		host = defaultBindHost()
	}
	db, logStore, logger, logCleanup, err := openStateAndLogging(debugLog)
	if err != nil {
		return nil, err
	}
	auditCleanup := func() {}
	var closeMetrics func()
	started := false
	defer func() {
		if !started {
			if closeMetrics != nil {
				closeMetrics()
			}
			auditCleanup()
			logCleanup()
		}
	}()

	serverCert, serverFP, serverKey, err := loadServerIdentity(db, logger)
	if err != nil {
		return nil, err
	}

	lanIP := resolveAdvertiseIP(advertiseIP, host)

	cfg := &config.ServerConfig{
		Port:           port,
		Host:           host,
		PollIntervalMs: 2000,
	}

	registry := pki.NewDeviceRegistry(db)
	users := pki.NewUserRegistry(db)
	// The raw server key is the cert-issuing CA; JWT signing must not share it.
	jwtKey, err := pki.DeriveJWTSigningKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("derive jwt key: %w", err)
	}
	sessionMgr := session.NewManager(jwtKey)

	srv := server.NewServer(cfg)
	srv.SetSecurityServices(sessionMgr, registry, users, serverKey)
	srv.SetPairingFingerprint(serverFP)
	srv.SetStateDB(db)

	auditLogger, auditLogCleanup := setupAuditLogger()
	auditCleanup = auditLogCleanup
	srv.SetAuditLogger(auditLogger)
	srv.SetLogSource(logStore)

	tlsCfg, err := pki.BuildMTLSConfig(serverCert)
	if err != nil {
		return nil, fmt.Errorf("mTLS config: %w", err)
	}
	srv.SetTLSConfig(tlsCfg)

	hostname, _ := os.Hostname()
	serverURL := httpsURL(lanIP, port)
	invites := pki.NewInviteStore(db)
	pairHandler := pair.NewPairingHandler(registry, users, invites, serverKey, serverFP, hostname, serverURL)
	pairHandler.SetAuditLogger(auditLogger)
	srv.RegisterPairRoute(pairHandler)
	srv.SetAdvertisedHost(lanIP)
	srv.RegisterTeamRoutes(users, registry, invites)
	srv.RegisterAdminRoutes(version)

	ctx, cancelCtx := context.WithCancel(context.Background())

	if withServices {
		pushStore := push.NewStore(db)
		srv.SetPushStore(pushStore)
		monStore := monitoring.NewStore(db)

		syncStore := datasync.NewSyncStore(db, monStore)
		srv.RegisterSyncRoutes(syncStore)
		srv.RegisterVaultRoutes(syncStore)
		startPeriodicCleanup(ctx, 24*time.Hour, func() {
			// Tombstones must outlive the longest plausible device offline period, or a returning device resurrects deleted records.
			syncStore.CleanupTombstones(365 * 24 * time.Hour)
		})

		metricsClose, metricErr := setupMetrics(ctx, srv, db, pushStore, registry, users, monStore, hostname, logger)
		if metricErr != nil {
			cancelCtx()
			return nil, metricErr
		}
		closeMetrics = metricsClose
		requests := metrics.NewRequestStore(db)
		srv.RegisterMetricRequestRoutes(requests, monStore)
	}

	// /api/ssh-configs is deliberately not registered: host SSH material moves only through the one-shot sync.

	srv.SetCapabilities(version)

	// Bind synchronously so a bind failure exits non-zero instead of leaving a listener-less process KeepAlive would consider healthy.
	if err := srv.Listen(); err != nil {
		cancelCtx()
		return nil, listenError(err, port)
	}
	go func() {
		// Anything but ErrServerClosed means the listener died; exit so the service manager restarts us.
		if srvErr := srv.Serve(ctx); srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "server error: %v\n", srvErr)
			os.Exit(1)
		}
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			// Drain in-flight requests before tearing down anything they still use.
			_ = srv.Shutdown(ctx)
			cancelCtx()
			if closeMetrics != nil {
				closeMetrics()
			}
			auditCleanup()
			logCleanup()
		})
	}

	started = true
	return &runningServer{
		srv:         srv,
		pairHandler: pairHandler,
		serverFP:    serverFP,
		ctx:         ctx,
		cancel:      stop,
	}, nil
}

func listenError(err error, port int) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("port %d is already in use. Is the PocketCmd service already running (`pcmd status`)? Use --port to pick another", port)
	}
	return fmt.Errorf("listen: %w", err)
}

func runFirstRun(cmd *cobra.Command, args []string) error {
	w := cmd.OutOrStdout()
	flags := cmd.Flags()
	port, _ := flags.GetInt("port")
	host, _ := flags.GetString("host")
	foreground, _ := flags.GetBool("foreground")
	advertiseIP, _ := flags.GetString("advertise-ip")
	debugLog, _ := flags.GetString("debug-log")
	pairTimeout, _ := flags.GetDuration("pair-timeout")

	nonInteractive, _ := flags.GetBool("non-interactive")

	if err := checkPrivileges(currentPrivileges()); err != nil {
		return err
	}

	cfgPath := config.ConfigFilePath()

	// Only a missing config.json counts as no config; an unreadable one must not be overwritten by the wizard.
	featureCfg, err := config.LoadFeatureConfig(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", cfgPath, err)
	}
	haveConfig := err == nil
	db, err := stateDB()
	if err != nil {
		return err
	}
	devices, _ := pki.NewDeviceRegistry(db).List()
	switch firstRunMode(haveConfig, len(devices)) {
	case runModeExisting:
		port, host, advertiseIP = runtimeSettings(cmd)
		foreground = foreground || featureCfg.ServiceMode == "foreground"
		return runExisting(w, port, host, debugLog, advertiseIP, foreground, featureCfg)
	case runModePairWithConfig:
		port, host, advertiseIP = runtimeSettings(cmd)
		if !flags.Changed("host") && featureCfg.Host == "" {
			host = ""
		}
	}
	skipPairing := len(devices) > 0

	var featureCfg2 config.FeatureConfig
	if !isInteractive(nonInteractive) {
		featureCfg2 = config.DefaultFeatureConfig()
		if foreground {
			featureCfg2.ServiceMode = "foreground"
		}
		if host == "" {
			host = defaultBindHost()
		}
	} else {
		var wizErr error
		featureCfg2, wizErr = runWizard(version, foreground, skipPairing, getAllLANIPs(), host)
		if wizErr != nil {
			return wizErr
		}
		host = featureCfg2.Host
	}
	featureCfg = featureCfg2
	featureCfg.Port = port
	featureCfg.Host = host
	featureCfg.AdvertiseIP = advertiseIP
	os.MkdirAll(config.PocketCmdDir(), 0700)

	if skipPairing {
		if err := config.SaveFeatureConfig(cfgPath, featureCfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		showMigrationSummary(w, featureCfg.ServiceMode)
		return nil
	}

	// config.json is written only after a device pairs, so a run that never paired leaves nothing behind and the retry repeats the whole flow.
	rs, err := startFullServer(port, host, debugLog, advertiseIP, true)
	if err != nil {
		return err
	}
	defer rs.cancel()

	lanIP := resolveAdvertiseIP(advertiseIP, host)
	token := rs.pairHandler.GeneratePairingToken()
	pairingURL := pairURL(lanIP, port, token, rs.serverFP)

	renderPairingInstructions(w, pairingURL, reachableIPs(host), port)

	// Tokens expire before the wait does, so each expiry swaps in a fresh token and QR.
	refresh := func() {
		token := rs.pairHandler.GeneratePairingToken()
		fmt.Fprintln(w, "  The pairing code expired. Scan the new code:")
		fmt.Fprintln(w)
		printPairingQR(w, pairURL(lanIP, port, token, rs.serverFP))
		fmt.Fprintln(w, "  Waiting for device...")
	}
	deviceName, deviceID, outcome := waitForPairing(rs.pairHandler, pairTimeout, rs.pairHandler.TokenTTL(), refresh)
	switch outcome {
	case pairingCancelled:
		fmt.Fprintln(w, "\n  Cancelled.")
		return errInterrupted
	case pairingTimedOut:
		return fmt.Errorf("no device paired within %s; run 'pcmd' again to retry (or pass --pair-timeout 0 to wait indefinitely)", pairTimeout)
	}

	if err := config.SaveFeatureConfig(cfgPath, featureCfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	showSuccess(w, deviceName, deviceID, featureCfg.ServiceMode)

	if featureCfg.ServiceMode == "background" {
		installBackgroundService(w, &featureCfg, port, host, rs.cancel)
	}

	if featureCfg.ServiceMode == "foreground" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Running in foreground. Press Ctrl+C to stop.")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Fprintln(w, "\n  Shutting down...")
	}

	return nil
}

type runMode int

const (
	runModePair runMode = iota
	runModePairWithConfig
	runModeMigrate
	runModeExisting
)

func firstRunMode(haveConfig bool, deviceCount int) runMode {
	switch {
	case haveConfig && deviceCount > 0:
		return runModeExisting
	case haveConfig:
		return runModePairWithConfig
	case deviceCount > 0:
		return runModeMigrate
	}
	return runModePair
}

func renderPairingInstructions(w io.Writer, pairingURL string, allIPs []string, port int) {
	fmt.Fprintln(w, "  Starting server...")
	fmt.Fprintln(w)

	if len(allIPs) > 1 {
		fmt.Fprintln(w, "  LAN addresses:")
		for _, ip := range allIPs {
			fmt.Fprintf(w, "    %s\n", httpsURL(ip, port))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "  Scan QR to pair your device:")
	fmt.Fprintln(w)

	printPairingQR(w, pairingURL)
	fmt.Fprintln(w, "  Waiting for device...")
}

type pairingOutcome int

const (
	pairingSuccess pairingOutcome = iota
	pairingCancelled
	pairingTimedOut
)

const firstRunPairingTimeout = 5 * time.Minute

type pairedDevice struct {
	name string
	id   string
}

func waitForPairing(pairHandler *pair.PairingHandler, timeout, refreshEvery time.Duration, refresh func()) (deviceName, deviceID string, outcome pairingOutcome) {
	paired := make(chan pairedDevice, 1)
	// The handler invokes this callback inline; a blocking send would stall the HTTP response.
	pairHandler.OnPairSuccess(func(deviceID, deviceName string) {
		select {
		case paired <- pairedDevice{deviceName, deviceID}:
		default:
		}
	})
	defer pairHandler.OnPairSuccess(nil)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	var deadline <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}

	p, outcome := awaitPairing(paired, sigCh, ticker.C, deadline, refresh)
	return p.name, p.id, outcome
}

func awaitPairing(paired <-chan pairedDevice, sig <-chan os.Signal, refreshTick, deadline <-chan time.Time, refresh func()) (pairedDevice, pairingOutcome) {
	for {
		select {
		case p := <-paired:
			return p, pairingSuccess
		case <-sig:
			return pairedDevice{}, pairingCancelled
		case <-deadline:
			return pairedDevice{}, pairingTimedOut
		case <-refreshTick:
			refresh()
		}
	}
}

func installBackgroundService(w io.Writer, cfg *config.FeatureConfig, port int, host string, stopServer func()) {
	binPath, _ := os.Executable()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Installing as background service...")
	warnings, err := svc.writeFile(binPath, port, host)
	printServiceWarnings(w, warnings)
	if err != nil {
		fmt.Fprintf(w, "  Warning: service install failed: %v\n", err)
		fmt.Fprintln(w, "  Running in foreground instead.")
		cfg.ServiceMode = "foreground"
		return
	}

	// Release the port first, or the daemon dies with EADDRINUSE until the restart backoff elapses.
	stopServer()

	if err := svc.start(); err != nil {
		fmt.Fprintf(w, "  Warning: service installed but failed to start: %v\n", err)
		fmt.Fprintln(w, "  Run 'pcmd restart' to try again.")
		return
	}
	if err := svc.waitHealthy(host, port, 10*time.Second); err == nil {
		fmt.Fprintln(w, "  Service installed and running.")
	} else {
		fmt.Fprintln(w, "  Warning: service installed but health check failed.")
	}
}

func runExisting(w io.Writer, port int, host, debugLog, advertiseIP string, foreground bool, featureCfg config.FeatureConfig) error {
	// The service unit runs us with --foreground; checking the service from inside it would find this process and loop.
	if !foreground {
		printBanner(w)
		err := ensureServiceRunning(w, port, host)
		if err == nil {
			return printServiceStatus(w, port)
		}
		fmt.Fprintf(w, "  Warning: %v\n", err)
		fmt.Fprintln(w, "  Running in foreground instead.")
		fmt.Fprintln(w)
	}

	rs, err := startFullServer(port, host, debugLog, advertiseIP, true)
	if err != nil {
		return err
	}
	defer rs.cancel()

	if foreground {
		printBanner(w)
	}
	fmt.Fprintln(w, "  Server running in foreground. Press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Fprintln(w, "\n  Shutting down...")
	return nil
}

func ensureServiceRunning(w io.Writer, port int, host string) error {
	if svc.isInstalled() {
		if svc.status().Running {
			return nil
		}
		fmt.Fprintln(w, "  Starting background service...")
		if err := svc.start(); err != nil {
			return fmt.Errorf("background service failed to start: %w", err)
		}
	} else {
		fmt.Fprintln(w, "  Installing as background service...")
		binPath, _ := os.Executable()
		warnings, err := svc.install(binPath, port, host)
		printServiceWarnings(w, warnings)
		if err != nil {
			return fmt.Errorf("background service install failed: %w", err)
		}
	}
	if err := svc.waitHealthy(host, port, 10*time.Second); err != nil {
		fmt.Fprintln(w, "  Warning: service started but health check failed. See 'pcmd status'.")
	}
	fmt.Fprintln(w)
	return nil
}

func printServiceStatus(w io.Writer, port int) error {
	status := svc.status()
	if status.Running {
		fmt.Fprintf(w, "  Status:   running (pid %d)\n", status.PID)
	} else {
		fmt.Fprintln(w, "  Status:   starting")
	}
	fmt.Fprintf(w, "  Port:     %d\n", port)

	db, err := stateDB()
	if err != nil {
		return err
	}
	devices, _ := pki.NewDeviceRegistry(db).List()
	fmt.Fprintf(w, "  Devices:  %d paired\n", countActiveDevices(devices))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  pcmd invite        Invite a device or team member")
	fmt.Fprintln(w, "  pcmd status        Detailed status")
	fmt.Fprintln(w, "  pcmd uninstall     Stop and remove service")
	return nil
}

func setupMetrics(ctx context.Context, srv *server.Server, db *sql.DB, pushStore *push.Store, registry *pki.DeviceRegistry, users *pki.UserRegistry, monStore *monitoring.Store, hostname string, logger *slog.Logger) (func(), error) {
	metricStore, err := metrics.NewMetricStore(config.PocketCmdDir())
	if err != nil {
		return nil, fmt.Errorf("metric store: %w", err)
	}

	relayURL := pushRelayURL(logger)
	logger.Info("[push] alert notifications go through the relay", "relay", relayURL)
	pushClient := push.NewPushClient(relayURL)
	evaluator := metrics.NewEvaluator(func(signalType, title, body string, data map[string]string) {
		regs, _ := pushStore.ReadAll()
		regs = filterRegsByAlertPermission(regs, registry, users, data["metric_id"], logger)
		if len(regs) == 0 {
			return
		}
		gone, err := pushClient.Notify(regs, push.Notification{
			SignalType: signalType,
			Title:      title,
			Body:       body,
			Sound:      "default",
			Data:       data,
		})
		for _, deviceID := range gone {
			if rmErr := pushStore.Remove(deviceID); rmErr != nil {
				logger.Error("[push] prune registration failed", "device_id", deviceID, "err", rmErr)
			} else {
				logger.Info("[push] pruned dead registration", "device_id", deviceID)
			}
		}
		if err != nil {
			logger.Error("[push] notify failed", "err", err)
		}
	}, hostname)
	evaluator.SetStateStore(metrics.NewAlertStateStore(db))
	scheduler := metrics.NewScheduler(metricStore, evaluator, monStore, logger)
	monStore.SetOnChange(scheduler.Reload)

	metricAPI := metrics.NewMetricAPI(metricStore, scheduler)
	srv.RegisterMetricRoutes(metricAPI)
	scheduler.Start(ctx)

	startPeriodicCleanup(ctx, 24*time.Hour, func() {
		// An out-of-range retention_days would overflow the Duration and delete every sample.
		retDays := metrics.ClampRetention(scheduler.GetConfig().RetentionDays)
		metricStore.Cleanup(time.Duration(retDays) * 24 * time.Hour)
	})

	return func() {
		scheduler.Stop()
		metricStore.Close()
	}, nil
}

func filterRegsByAlertPermission(regs []push.PushRegistration, devices *pki.DeviceRegistry, users *pki.UserRegistry, metricID string, logger *slog.Logger) []push.PushRegistration {
	out := regs[:0]
	for _, reg := range regs {
		dev, err := devices.FindByID(reg.DeviceID)
		if err != nil || dev == nil || dev.Status != "active" || dev.UserID == "" {
			continue
		}
		u, err := users.FindByID(dev.UserID)
		if err != nil || u == nil {
			continue
		}
		if !authz.AlertMetricAllowed(u, metricID) {
			continue
		}
		out = append(out, reg)
	}
	return out
}

func startPeriodicCleanup(ctx context.Context, interval time.Duration, fn func()) {
	go func() {
		// Run once at startup so a server restarting more often than the interval still prunes.
		fn()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fn()
			}
		}
	}()
}
