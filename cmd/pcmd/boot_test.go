package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/push"
	"github.com/pocketcmd/pocketcmd-server/internal/server"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func insecureClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

func healthStatus(t *testing.T, port int) (int, map[string]any) {
	t.Helper()
	resp, err := insecureClient().Get(fmt.Sprintf("https://127.0.0.1:%d/api/health", port))
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	return resp.StatusCode, body
}

func TestStartFullServer_ServesHealthAndStopsCleanly(t *testing.T) {
	testutil.TempHome(t)
	port, err := pickFreePort("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	debugLog := filepath.Join(t.TempDir(), "debug.log")

	rs, err := startFullServer(port, "127.0.0.1", debugLog, "127.0.0.1", true)
	if err != nil {
		t.Fatalf("startFullServer: %v", err)
	}
	if rs.srv == nil || rs.pairHandler == nil || rs.ctx == nil || len(rs.serverFP) != 64 {
		t.Fatalf("incomplete handle: %+v", rs)
	}

	status, body := healthStatus(t, port)
	if status != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("health = %d %v", status, body)
	}
	checks, _ := body["checks"].(map[string]any)
	if checks["db"] != "ok" || checks["devices"] != "ok" || checks["tls"] != "ok" {
		t.Fatalf("health checks = %v", checks)
	}

	if _, fp, err := pki.LoadOrGenerateServerCert(config.TLSDir()); err != nil || fp != rs.serverFP {
		t.Fatalf("fingerprint on disk %q (err %v), handle %q", fp, err, rs.serverFP)
	}
	if _, err := os.Stat(filepath.Join(config.PocketCmdDir(), "metrics.db")); err != nil {
		t.Fatalf("metrics store not opened: %v", err)
	}
	if rs.pairHandler.GeneratePairingToken() == "" {
		t.Fatal("pairing handler is not wired")
	}

	rs.cancel()
	rs.cancel()

	if err := rs.ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("background context not cancelled: %v", err)
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port still held after stop: %v", err)
	}
	l.Close()
	if _, err := insecureClient().Get(fmt.Sprintf("https://127.0.0.1:%d/api/health", port)); err == nil {
		t.Fatal("server still answering after stop")
	}
	if b, err := os.ReadFile(debugLog); err != nil || !bytes.Contains(b, []byte(`"msg"`)) {
		t.Fatalf("debug log not written: %v %q", err, b)
	}
}

func TestStartFullServer_PairingOnlyOmitsServices(t *testing.T) {
	testutil.TempHome(t)
	port, err := pickFreePort("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := startFullServer(port, "127.0.0.1", "", "127.0.0.1", false)
	if err != nil {
		t.Fatalf("startFullServer: %v", err)
	}
	defer rs.cancel()

	if status, _ := healthStatus(t, port); status != http.StatusOK {
		t.Fatalf("health = %d", status)
	}
	if _, err := os.Stat(filepath.Join(config.PocketCmdDir(), "metrics.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pairing-only server must not open the metric store: %v", err)
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d/api/metrics/latest", port), nil)
	req.Header.Set(server.APIVersionHeader, server.APIVersion)
	resp, err := insecureClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics route on pairing-only server: %d", resp.StatusCode)
	}
}

func TestStartFullServer_PortInUse(t *testing.T) {
	testutil.TempHome(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	_, err = startFullServer(port, "127.0.0.1", "", "127.0.0.1", false)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected the port-in-use error, got %v", err)
	}
}

func TestLoadServerIdentity_WarnsWhenCertRegeneratedWithDevices(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	cert, fp, key, err := loadServerIdentity(db, logger)
	if err != nil || len(cert.Certificate) == 0 || len(fp) != 64 || key == nil {
		t.Fatalf("fresh identity: %v fp=%q", err, fp)
	}
	if strings.Contains(logs.String(), "re-pair") {
		t.Fatalf("unexpected warning: %s", logs.String())
	}
	if _, fp2, _, err := loadServerIdentity(db, logger); err != nil || fp2 != fp {
		t.Fatalf("reload: %v %q != %q", err, fp2, fp)
	}

	u, err := pki.NewUserRegistry(db).Create("owner", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.NewDeviceRegistry(db).RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Phone", u.UserID, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(config.TLSDir()); err != nil {
		t.Fatal(err)
	}
	_, fp3, _, err := loadServerIdentity(db, logger)
	if err != nil || fp3 == fp {
		t.Fatalf("regenerate: %v %q", err, fp3)
	}
	if !strings.Contains(logs.String(), "paired devices must re-pair") || !strings.Contains(logs.String(), "paired_devices=1") {
		t.Fatalf("missing warning: %s", logs.String())
	}
}

func TestInstallBackgroundService(t *testing.T) {
	run := func(f *fakeService) (string, config.FeatureConfig, int) {
		f.bind(t)
		cfg := config.FeatureConfig{ServiceMode: "background"}
		stops := 0
		out := discard()
		installBackgroundService(out, &cfg, 8767, "0.0.0.0", func() { stops++ })
		return out.String(), cfg, stops
	}

	out, cfg, stops := run(&fakeService{writeErr: errors.New("read-only fs")})
	if cfg.ServiceMode != "foreground" || stops != 0 || !strings.Contains(out, "read-only fs") || !strings.Contains(out, "Running in foreground instead") {
		t.Fatalf("write failure: mode=%s stops=%d out=%q", cfg.ServiceMode, stops, out)
	}

	f := &fakeService{startErr: errors.New("unit masked")}
	out, cfg, stops = run(f)
	if cfg.ServiceMode != "background" || stops != 1 || !strings.Contains(out, "failed to start: unit masked") || !strings.Contains(out, "pcmd restart") {
		t.Fatalf("start failure: mode=%s stops=%d out=%q", cfg.ServiceMode, stops, out)
	}
	if strings.Join(f.calls, ",") != "write,start" {
		t.Fatalf("calls = %v", f.calls)
	}

	f = &fakeService{healthy: true}
	out, cfg, stops = run(f)
	if cfg.ServiceMode != "background" || stops != 1 || !strings.Contains(out, "Service installed and running.") {
		t.Fatalf("healthy: mode=%s stops=%d out=%q", cfg.ServiceMode, stops, out)
	}
	if strings.Join(f.calls, ",") != "write,start" || !f.installed || !f.running {
		t.Fatalf("calls = %v installed=%v running=%v", f.calls, f.installed, f.running)
	}

	out, _, _ = run(&fakeService{})
	if !strings.Contains(out, "health check failed") {
		t.Fatalf("unhealthy: out=%q", out)
	}
}

func TestRotateServerCert_ReplacesIdentity(t *testing.T) {
	testutil.TempHome(t)
	f := noServer(t)
	tlsDir := config.TLSDir()
	_, oldFP, err := pki.LoadOrGenerateServerCert(tlsDir)
	if err != nil {
		t.Fatal(err)
	}
	oldCrt, _ := os.ReadFile(filepath.Join(tlsDir, "server.crt"))
	oldKey, _ := os.ReadFile(filepath.Join(tlsDir, "server.key"))

	stdout, _, err := runCLI(t, "rotate-server-cert", "--yes", "--no-qr", "--advertise-ip", "127.0.0.1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	out := stdout.String()
	_, newFP, err := pki.LoadOrGenerateServerCert(tlsDir)
	if err != nil {
		t.Fatal(err)
	}
	if newFP == oldFP {
		t.Fatal("fingerprint unchanged")
	}
	if !strings.Contains(out, "New fingerprint: "+shortFP(newFP)) || !strings.Contains(out, "Ctrl+C") {
		t.Fatalf("out = %q", out)
	}
	newCrt, _ := os.ReadFile(filepath.Join(tlsDir, "server.crt"))
	newKey, _ := os.ReadFile(filepath.Join(tlsDir, "server.key"))
	if bytes.Equal(oldCrt, newCrt) || bytes.Equal(oldKey, newKey) || len(newCrt) == 0 || len(newKey) == 0 {
		t.Fatal("old certificate or key still on disk")
	}
	entries, _ := os.ReadDir(tlsDir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(tlsDir, e.Name()))
		if bytes.Equal(b, oldCrt) || bytes.Equal(b, oldKey) {
			t.Fatalf("old material kept as %s", e.Name())
		}
	}
	if !strings.Contains(out, "fp="+newFP) && !strings.Contains(out, newFP) {
		t.Fatalf("re-pair URL does not carry the new fingerprint: %q", out)
	}
	if len(f.calls) != 0 {
		t.Fatalf("no service is installed, nothing to restart: %v", f.calls)
	}

	f.installed, f.running, f.matches, f.healthy = true, true, true, true
	stdout, _, err = runCLI(t, "rotate-server-cert", "-y", "--no-qr", "--advertise-ip", "127.0.0.1")
	if err != nil {
		t.Fatalf("rotate with service: %v", err)
	}
	if strings.Join(f.calls, ",") != "stop,start" || !strings.Contains(stdout.String(), "Service restarted successfully.") {
		t.Fatalf("calls=%v out=%q", f.calls, stdout.String())
	}
	if _, fp3, _ := pki.LoadOrGenerateServerCert(tlsDir); fp3 == newFP {
		t.Fatal("second rotation kept the certificate")
	}
}

func TestSetupMetrics_WiresStoreAndCloser(t *testing.T) {
	for _, c := range []struct {
		env     string
		wantLog string
	}{
		{"", "alert notifications go through the relay\" relay=" + config.DefaultPushRelayURL},
		{"http://127.0.0.1:9", "alert notifications go through the relay\" relay=http://127.0.0.1:9"},
	} {
		t.Setenv(pushRelayEnv, c.env)
		// A fresh HOME per case: the previous store's startup cleanup may still hold metrics.db.
		testutil.TempHome(t)
		db := testStateDB(t)
		if _, _, err := pki.LoadOrGenerateServerCert(config.TLSDir()); err != nil {
			t.Fatal(err)
		}
		serverKey, err := pki.LoadServerKey(config.TLSDir())
		if err != nil {
			t.Fatal(err)
		}
		registry := pki.NewDeviceRegistry(db)
		users := pki.NewUserRegistry(db)
		srv := server.NewServer(&config.ServerConfig{Port: 0, Host: "127.0.0.1", PollIntervalMs: 2000})
		srv.SetSecurityServices(session.NewManager(serverKey), registry, users, serverKey)
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		ctx, cancel := context.WithCancel(context.Background())

		closer, err := setupMetrics(ctx, srv, db, push.NewStore(db), registry, users, monitoring.NewStore(db), "host", logger)
		if err != nil {
			t.Fatalf("env=%q: %v", c.env, err)
		}
		if _, err := os.Stat(filepath.Join(config.PocketCmdDir(), "metrics.db")); err != nil {
			t.Fatalf("env=%q: metric store not created: %v", c.env, err)
		}
		if !strings.Contains(logs.String(), c.wantLog) {
			t.Errorf("env=%q: expected %q in %q", c.env, c.wantLog, logs.String())
		}
		cancel()
		done := make(chan struct{})
		go func() { closer(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("env=%q: closer hung", c.env)
		}
	}
}

func TestFilterRegsByAlertPermission(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	users := pki.NewUserRegistry(db)
	devices := pki.NewDeviceRegistry(db)
	admin, _ := users.Create("admin", "admin", "")
	scoped, _ := users.Create("scoped", "member", "")
	none, _ := users.Create("none", "member", "")
	if err := users.SetPermissions(scoped.UserID, pki.PermissionSet{"alerts.read": {Granted: true, Metrics: []string{"custom:cpu"}}}); err != nil {
		t.Fatal(err)
	}
	adminDev, _ := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "a", admin.UserID, "")
	scopedDev, _ := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "s", scoped.UserID, "")
	noneDev, _ := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "n", none.UserID, "")
	revokedDev, _ := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "r", admin.UserID, "")
	if err := devices.Revoke(revokedDev); err != nil {
		t.Fatal(err)
	}
	regs := []push.PushRegistration{
		{DeviceID: adminDev}, {DeviceID: scopedDev}, {DeviceID: noneDev}, {DeviceID: revokedDev}, {DeviceID: "unknown"},
	}
	logger := slog.New(slog.NewTextHandler(discard(), nil))

	ids := func(regs []push.PushRegistration) string {
		var out []string
		for _, r := range regs {
			out = append(out, r.DeviceID)
		}
		return strings.Join(out, ",")
	}
	cpu := filterRegsByAlertPermission(append([]push.PushRegistration(nil), regs...), devices, users, "custom:cpu", logger)
	if got := ids(cpu); got != adminDev+","+scopedDev {
		t.Fatalf("cpu recipients = %s", got)
	}
	mem := filterRegsByAlertPermission(append([]push.PushRegistration(nil), regs...), devices, users, "custom:mem", logger)
	if got := ids(mem); got != adminDev {
		t.Fatalf("memory recipients = %s", got)
	}
}
