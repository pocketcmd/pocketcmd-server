// Command e2e-test starts a local server and drives the suite against it.
// The seeded uptime metric reads /proc/uptime, so a full pass needs Linux.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pair"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/push"
	"github.com/pocketcmd/pocketcmd-server/internal/server"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
	"github.com/pocketcmd/pocketcmd-server/internal/state"

	"context"
)

const testPort = 18767

type adminCredentials struct {
	key         *ecdsa.PrivateKey
	certPEM     []byte
	jwt         string
	userID      string
	displayName string
}

func main() {
	fmt.Println("=== E2E Metrics Test ===")
	passed := 0
	failed := 0

	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("FAIL: %s: %v\n", name, err)
			failed++
		} else {
			fmt.Printf("PASS: %s\n", name)
			passed++
		}
	}

	srvComp := startTestServer()
	defer srvComp.cancel()

	clientKey, clientCertPEM, adminUserID, adminDisplayName, err := pairDevice(srvComp.pairHandler, "E2E Admin")
	if err != nil {
		fmt.Printf("FATAL: pairing failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: device paired")
	passed++

	httpClient, _, err := buildMTLSClient(clientKey, clientCertPEM)
	if err != nil {
		fmt.Printf("FATAL: mTLS client setup failed: %v\n", err)
		os.Exit(1)
	}

	jwt, err := getSession(httpClient, srvComp.registry)
	check("get JWT session", err)
	if err != nil {
		fmt.Printf("FATAL: cannot proceed without JWT\n")
		os.Exit(1)
	}
	_ = srvComp.ctx

	admin := adminCredentials{
		key:         clientKey,
		certPEM:     clientCertPEM,
		jwt:         jwt,
		userID:      adminUserID,
		displayName: adminDisplayName,
	}

	fmt.Println("Waiting 5s for metric collection...")
	time.Sleep(5 * time.Second)

	check("metrics available endpoint", testMetricsAvailable(httpClient, jwt, clientCertPEM))

	check("metrics latest has data", testMetricsLatest(httpClient, jwt, clientCertPEM))

	check("custom:e2e-answer collected", testMetricExists(httpClient, jwt, clientCertPEM, "custom:e2e-answer"))
	check("custom:e2e-uptime collected", testMetricExists(httpClient, jwt, clientCertPEM, "custom:e2e-uptime"))

	check("metrics series endpoint", testMetricsSeries(httpClient, jwt, clientCertPEM, "custom:e2e-uptime"))

	check("health endpoint", testHealth())

	check("sync push dashboard", testSyncPushDashboard(httpClient, jwt))
	check("sync pull dashboard roundtrip", testSyncPullDashboard(httpClient, jwt))

	check("sync dashboard type accepted", testSyncDashboardTypeAccepted(httpClient, jwt))

	check("sync push rejection reasons", testSyncPushRejectionReasons(httpClient, jwt))
	check("sync push stamps authenticated device id", testSyncPushDeviceStamp(httpClient, jwt, srvComp.registry))

	fmt.Println("\n=== Team Flow ===")
	teamPassed, teamFailed := teamFlow(srvComp, admin)
	passed += teamPassed
	failed += teamFailed

	fmt.Println("\n=== Extended Flow ===")
	extPassed, extFailed := extendedFlow(srvComp, admin)
	passed += extPassed
	failed += extFailed

	fmt.Println("\n=== Sync Scoping Flow ===")
	syncPassed, syncFailed := syncScopingFlow(srvComp, admin)
	passed += syncPassed
	failed += syncFailed

	fmt.Println("\n=== Vault Flow ===")
	vPassed, vFailed := vaultFlow(srvComp, admin)
	passed += vPassed
	failed += vFailed

	fmt.Println("\n=== Device Flow ===")
	devPassed, devFailed := deviceFlow(srvComp, admin)
	passed += devPassed
	failed += devFailed

	// coreFlow runs last: its SSH export claims the server's single fetch.
	fmt.Println("\n=== Core Flow ===")
	cPassed, cFailed := coreFlow(srvComp, admin)
	passed += cPassed
	failed += cFailed

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

type testServerComponents struct {
	ctx         context.Context
	cancel      context.CancelFunc
	srv         *server.Server
	pairHandler *pair.PairingHandler
	serverKey   *ecdsa.PrivateKey
	registry    *pki.DeviceRegistry
	users       *pki.UserRegistry
	invites     *pki.InviteStore
	serverFP    string
}

func startTestServer() testServerComponents {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	serverCert, serverFP, err := pki.LoadOrGenerateServerCert(config.TLSDir())
	if err != nil {
		fmt.Printf("FATAL: TLS setup: %v\n", err)
		os.Exit(1)
	}

	serverKey, err := pki.LoadServerKey(config.TLSDir())
	if err != nil {
		fmt.Printf("FATAL: server key: %v\n", err)
		os.Exit(1)
	}

	cfg := &config.ServerConfig{
		Port:           testPort,
		Host:           "0.0.0.0",
		PollIntervalMs: 2000,
	}

	db, err := state.Open(config.PocketCmdDir())
	if err != nil {
		fmt.Printf("FATAL: state.db: %v\n", err)
		os.Exit(1)
	}
	registry := pki.NewDeviceRegistry(db)
	users := pki.NewUserRegistry(db)
	sessionMgr := session.NewManager(serverKey)

	// NewServer captures slog's default logger, so set it first.
	logStore := server.NewLogStore(db, 10000)
	slog.SetDefault(slog.New(server.NewTeeHandler(
		server.NewBufferHandler(logStore), slog.NewTextHandler(os.Stderr, nil))))
	auditFile, err := os.OpenFile(filepath.Join(config.PocketCmdDir(), "audit.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("FATAL: audit.log: %v\n", err)
		os.Exit(1)
	}
	auditLogger := slog.New(slog.NewJSONHandler(auditFile, nil))

	srv := server.NewServer(cfg)
	srv.SetSecurityServices(sessionMgr, registry, users, serverKey)
	srv.SetPairingFingerprint(serverFP)
	srv.SetStateDB(db)
	srv.SetAuditLogger(auditLogger)
	srv.SetLogSource(logStore)
	srv.SetCapabilities("e2e-test")

	tlsCfg, err := pki.BuildMTLSConfig(serverCert)
	if err != nil {
		fmt.Printf("FATAL: mTLS config: %v\n", err)
		os.Exit(1)
	}
	srv.SetTLSConfig(tlsCfg)

	serverURL := fmt.Sprintf("https://127.0.0.1:%d", testPort)
	invites := pki.NewInviteStore(db)
	pairHandler := pair.NewPairingHandler(registry, users, invites, serverKey, serverFP, "e2e-test", serverURL)
	pairHandler.SetAuditLogger(auditLogger)
	srv.RegisterPairRoute(pairHandler)

	srv.RegisterTeamRoutes(users, registry, invites)

	srv.RegisterAdminRoutes("e2e-test")

	srv.RegisterSSHRoutes()

	monStore := monitoring.NewStore(db)
	srv.SetPushStore(push.NewStore(db))

	syncStore := datasync.NewSyncStore(db, monStore)
	srv.RegisterSyncRoutes(syncStore)
	srv.RegisterVaultRoutes(syncStore)

	metricStore, err := metrics.NewMetricStore(config.PocketCmdDir())
	if err != nil {
		fmt.Printf("FATAL: metric store: %v\n", err)
		os.Exit(1)
	}

	// The default config collects nothing; seed the custom metrics the suite asserts on.
	monitoringCfg := json.RawMessage(`{` +
		`"default_interval_seconds":5,"retention_days":7,"custom_metrics":[` +
		`{"id":"e2e-answer","label":"Answer","command":"echo 42"},` +
		`{"id":"e2e-uptime","label":"Uptime","command":"cut -d' ' -f1 /proc/uptime"}]}`)
	pushRes, err := syncStore.PushRecords("", []datasync.SyncRecord{{
		ID: "monitoring_config", Type: "monitoring_config",
		SchemaVersion: 1, UpdatedAt: 1, Data: monitoringCfg,
	}})
	if err != nil || len(pushRes.Accepted) != 1 {
		fmt.Printf("FATAL: monitoring config seed: %v (%+v)\n", err, pushRes)
		os.Exit(1)
	}

	evaluator := metrics.NewEvaluator(func(string, string, string, map[string]string) {}, "e2e-test")
	scheduler := metrics.NewScheduler(metricStore, evaluator, monStore, logger)
	monStore.SetOnChange(scheduler.Reload)

	metricAPI := metrics.NewMetricAPI(metricStore, scheduler)
	srv.RegisterMetricRoutes(metricAPI)
	srv.RegisterMetricRequestRoutes(metrics.NewRequestStore(db), monStore)

	ctx, cancel := context.WithCancel(context.Background())
	scheduler.Start(ctx)

	go srv.Start(ctx)
	time.Sleep(500 * time.Millisecond)

	return testServerComponents{
		ctx:         ctx,
		cancel:      cancel,
		srv:         srv,
		pairHandler: pairHandler,
		serverKey:   serverKey,
		registry:    registry,
		users:       users,
		invites:     invites,
		serverFP:    serverFP,
	}
}

func pairDevice(handler *pair.PairingHandler, displayName string) (*ecdsa.PrivateKey, []byte, string, string, error) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("generate key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&clientKey.PublicKey)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("marshal pubkey: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "e2e-test-device"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, clientKey)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	token := handler.GeneratePairingToken()

	pairReq := pair.PairRequest{
		DevicePublicKey: string(pubPEM),
		DeviceName:      "e2e-test-device",
		CSR:             string(csrPEM),
		Credential:      pair.PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     displayName,
	}
	body, _ := json.Marshal(pairReq)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req := newRequest("POST", fmt.Sprintf("https://127.0.0.1:%d/api/pair", testPort), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("pair request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, nil, "", "", fmt.Errorf("pair status %d: %s", resp.StatusCode, respBody)
	}

	var pairResp pair.PairResponse
	if err := json.NewDecoder(resp.Body).Decode(&pairResp); err != nil {
		return nil, nil, "", "", fmt.Errorf("decode pair response: %w", err)
	}

	return clientKey, []byte(pairResp.ClientCert), pairResp.UserID, pairResp.UserDisplayName, nil
}

func buildMTLSClient(clientKey *ecdsa.PrivateKey, clientCertPEM []byte) (*http.Client, []byte, error) {
	clientCert, err := tls.X509KeyPair(clientCertPEM, encodeECKey(clientKey))
	if err != nil {
		return nil, nil, fmt.Errorf("x509 key pair: %w", err)
	}

	block, _ := pem.Decode(clientCertPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("decode cert PEM")
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				InsecureSkipVerify: true,
			},
		},
	}, block.Bytes, nil
}

func encodeECKey(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func getSession(client *http.Client, registry *pki.DeviceRegistry) (string, error) {
	req := newRequest("POST", fmt.Sprintf("https://127.0.0.1:%d/api/session", testPort), nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("session request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("session status %d: %s", resp.StatusCode, string(body))
	}

	var sessResp struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sessResp); err != nil {
		return "", fmt.Errorf("decode session: %w", err)
	}

	if sessResp.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}

	return sessResp.Token, nil
}

func newRequest(method, url string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, url, body)
	req.Header.Set(server.APIVersionHeader, server.APIVersion)
	return req
}

func authedGet(client *http.Client, jwt, url string) (*http.Response, error) {
	req := newRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	return client.Do(req)
}

func authedPost(client *http.Client, jwt, url string, body []byte) (*http.Response, error) {
	req := newRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func testHealth() error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/health", testPort))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func testMetricsAvailable(client *http.Client, jwt string, _ []byte) error {
	resp, err := authedGet(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/metrics/available", testPort))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Metrics []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"metrics"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(result.Metrics) != 2 {
		return fmt.Errorf("expected exactly the 2 seeded custom metrics, got %d", len(result.Metrics))
	}
	for _, m := range result.Metrics {
		if !strings.HasPrefix(m.ID, "custom:") {
			return fmt.Errorf("unexpected non-custom metric %q in catalog", m.ID)
		}
	}
	return nil
}

func testMetricsLatest(client *http.Client, jwt string, _ []byte) error {
	resp, err := authedGet(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/metrics/latest", testPort))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Metrics map[string]map[string]interface{} `json:"metrics"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(result.Metrics) == 0 {
		return fmt.Errorf("no metrics collected yet")
	}
	fmt.Printf("  collected %d metric groups\n", len(result.Metrics))
	for id := range result.Metrics {
		fmt.Printf("    %s\n", id)
	}
	return nil
}

func testMetricExists(client *http.Client, jwt string, _ []byte, metricID string) error {
	resp, err := authedGet(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/metrics/latest", testPort))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Metrics map[string]map[string]interface{} `json:"metrics"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if _, ok := result.Metrics[metricID]; !ok {
		return fmt.Errorf("%s not found in latest metrics", metricID)
	}
	return nil
}

func testMetricsSeries(client *http.Client, jwt string, _ []byte, metricID string) error {
	url := fmt.Sprintf("https://127.0.0.1:%d/api/metrics/series?metric=%s&range=1h", testPort, metricID)
	resp, err := authedGet(client, jwt, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Metric string        `json:"metric"`
		Points []interface{} `json:"points"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if result.Metric != metricID {
		return fmt.Errorf("expected metric %s, got %s", metricID, result.Metric)
	}
	return nil
}

func testSyncPushDashboard(client *http.Client, jwt string) error {
	dashData := map[string]interface{}{
		"name":         "Docker Overview",
		"taskId":       "task-e2e",
		"sortOrder":    1,
		"componentIds": []string{"comp-cpu", "comp-mem"},
	}
	dashJSON, _ := json.Marshal(dashData)

	record := map[string]interface{}{
		"records": []map[string]interface{}{
			{
				"id":             "dash-e2e-1",
				"type":           "dashboard",
				"schema_version": 1,
				"updated_at":     time.Now().UnixMilli(),
				"device_id":      "e2e-device",
				"deleted":        false,
				"data":           json.RawMessage(dashJSON),
			},
		},
	}
	body, _ := json.Marshal(record)

	resp, err := authedPost(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/sync/push", testPort), body)
	if err != nil {
		return fmt.Errorf("push request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Accepted []string                  `json:"accepted"`
		Rejected []datasync.RejectedRecord `json:"rejected"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode push result: %w", err)
	}

	if len(result.Accepted) != 1 || result.Accepted[0] != "dash-e2e-1" {
		return fmt.Errorf("expected dash-e2e-1 accepted, got accepted=%v rejected=%v", result.Accepted, result.Rejected)
	}
	return nil
}

func testSyncPushRejectionReasons(client *http.Client, jwt string) error {
	now := time.Now().UnixMilli()
	body, _ := json.Marshal(map[string]interface{}{
		"records": []map[string]interface{}{
			{"id": "dash-e2e-1", "type": "dashboard", "schema_version": 1, "updated_at": 1, "data": json.RawMessage(`{}`)},
			{"id": "rej-type", "type": "not_a_type", "schema_version": 1, "updated_at": now, "data": json.RawMessage(`{}`)},
			{"id": "bad id!", "type": "task", "schema_version": 1, "updated_at": now, "data": json.RawMessage(`{}`)},
			{"id": "rej-future", "type": "task", "schema_version": 1, "updated_at": now + 10*60*1000, "data": json.RawMessage(`{}`)},
			{"id": "rej-wrap", "type": "vault_wrap", "schema_version": 1, "updated_at": now, "data": json.RawMessage(`{}`)},
			{"id": "rej-dev", "type": "device_revocation", "schema_version": 1, "updated_at": now, "deleted": true, "data": json.RawMessage(`{}`)},
			{"id": "rej-mon", "type": "monitoring_config", "schema_version": 1, "updated_at": now, "data": json.RawMessage(`{}`)},
		},
	})
	resp, err := authedPost(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/sync/push", testPort), body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push status %d: %s", resp.StatusCode, respBody)
	}
	var result struct {
		Accepted []string                  `json:"accepted"`
		Rejected []datasync.RejectedRecord `json:"rejected"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode push result: %w", err)
	}
	want := map[string]string{
		"dash-e2e-1": datasync.RejectSuperseded,
		"rej-type":   datasync.RejectInvalidIDOrType,
		"bad id!":    datasync.RejectInvalidIDOrType,
		"rej-future": datasync.RejectFutureTimestamp,
		"rej-wrap":   datasync.RejectInvalidVaultRecordID,
		"rej-dev":    datasync.RejectRevocationDeleteForbidden,
		"rej-mon":    datasync.RejectMonitoringUnsupported,
	}
	if len(result.Accepted) != 0 || len(result.Rejected) != len(want) {
		return fmt.Errorf("expected %d rejections and no acceptance, got %+v", len(want), result)
	}
	for _, rej := range result.Rejected {
		if want[rej.ID] != rej.Reason {
			return fmt.Errorf("record %q: reason %q, want %q", rej.ID, rej.Reason, want[rej.ID])
		}
	}
	return nil
}

func testSyncPushDeviceStamp(client *http.Client, jwt string, registry *pki.DeviceRegistry) error {
	body, _ := json.Marshal(map[string]interface{}{
		"records": []map[string]interface{}{{
			"id": "stamp-e2e-1", "type": "task", "schema_version": 1,
			"updated_at": time.Now().UnixMilli(), "device_id": "forged-device",
			"data": json.RawMessage(`{"v":1}`),
		}},
	})
	resp, err := authedPost(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/sync/push", testPort), body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("push status %d", resp.StatusCode)
	}
	pullBody, _ := json.Marshal(map[string][]string{"ids": {"stamp-e2e-1"}})
	resp, err = authedPost(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/sync/pull", testPort), pullBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result struct {
		Records []datasync.SyncRecord `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode pull: %w", err)
	}
	if len(result.Records) != 1 {
		return fmt.Errorf("expected 1 record, got %d", len(result.Records))
	}
	devices, err := registry.List()
	if err != nil {
		return err
	}
	for _, d := range devices {
		if d.DeviceID == result.Records[0].DeviceID && d.Status == pki.DeviceStatusActive {
			return nil
		}
	}
	return fmt.Errorf("device_id %q is not a registered device (client value was not overwritten)", result.Records[0].DeviceID)
}

func testSyncPullDashboard(client *http.Client, jwt string) error {
	pullReq := map[string][]string{"ids": {"dash-e2e-1"}}
	body, _ := json.Marshal(pullReq)

	resp, err := authedPost(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/sync/pull", testPort), body)
	if err != nil {
		return fmt.Errorf("pull request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Records []struct {
			ID   string          `json:"id"`
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode pull result: %w", err)
	}

	if len(result.Records) != 1 {
		return fmt.Errorf("expected 1 record, got %d", len(result.Records))
	}

	rec := result.Records[0]
	if rec.ID != "dash-e2e-1" {
		return fmt.Errorf("expected id dash-e2e-1, got %s", rec.ID)
	}
	if rec.Type != "dashboard" {
		return fmt.Errorf("expected type dashboard, got %s", rec.Type)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(rec.Data, &data); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}
	if data["name"] != "Docker Overview" {
		return fmt.Errorf("expected name 'Docker Overview', got %v", data["name"])
	}
	if data["taskId"] != "task-e2e" {
		return fmt.Errorf("expected taskId 'task-e2e', got %v", data["taskId"])
	}
	compIds, ok := data["componentIds"].([]interface{})
	if !ok || len(compIds) != 2 {
		return fmt.Errorf("expected 2 componentIds, got %v", data["componentIds"])
	}
	return nil
}

func teamFlow(srvComp testServerComponents, admin adminCredentials) (int, int) {
	passed := 0
	failed := 0
	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("FAIL: %s: %v\n", name, err)
			failed++
		} else {
			fmt.Printf("PASS: %s\n", name)
			passed++
		}
	}

	serverURL := fmt.Sprintf("https://127.0.0.1:%d", testPort)

	if admin.userID == "" {
		check("Team: bootstrap admin has user_id", fmt.Errorf("user_id empty"))
		return passed, failed
	}
	check("Team: bootstrap admin has user_id", nil)
	if admin.displayName != "E2E Admin" {
		check("Team: bootstrap admin has display_name", fmt.Errorf("got %q", admin.displayName))
	} else {
		check("Team: bootstrap admin has display_name", nil)
	}

	adminHTTP, _, err := buildMTLSClient(admin.key, admin.certPEM)
	if err != nil {
		check("Team: admin mTLS client", err)
		return passed, failed
	}
	check("Team: admin mTLS client", nil)

	inviteCode, err := createInviteHTTP(adminHTTP, admin.jwt, serverURL)
	check("Team: admin creates invite", err)
	if err != nil {
		return passed, failed
	}

	memberKey, memberCertPEM, memberUserID, err := redeemInvite(
		srvComp.pairHandler, inviteCode, "E2E Member",
	)
	check("Team: member redeems invite", err)
	if err != nil {
		return passed, failed
	}
	if memberUserID == admin.userID {
		check("Team: member gets distinct user_id", fmt.Errorf("member user_id %q == admin user_id %q", memberUserID, admin.userID))
	} else {
		check("Team: member gets distinct user_id", nil)
	}

	memberDevices, devErr := srvComp.registry.DevicesByUserID(memberUserID)
	if devErr != nil {
		check("Team: member device count", devErr)
	} else if len(memberDevices) != 1 {
		check("Team: member device count", fmt.Errorf("expected 1, got %d", len(memberDevices)))
	} else {
		check("Team: member device count = 1", nil)
	}

	memberHTTP, _, err := buildMTLSClient(memberKey, memberCertPEM)
	if err != nil {
		check("Team: member mTLS client", err)
		return passed, failed
	}
	check("Team: member mTLS client", nil)

	memberJWT, err := getSession(memberHTTP, srvComp.registry)
	check("Team: member JWT session", err)
	if err != nil {
		return passed, failed
	}

	check("Team: member can access metrics/available",
		testMetricsAvailable(memberHTTP, memberJWT, memberCertPEM))

	check("Team: member blocked from /api/ssh-configs",
		expectForbidden(memberHTTP, memberJWT, serverURL+"/api/ssh-configs"))

	check("Team: admin revokes member user",
		deleteUserHTTP(adminHTTP, admin.jwt, serverURL, memberUserID))

	check("Team: revoked member cert renewal rejected",
		expectCertRenewForbidden(memberHTTP, memberKey, memberCertPEM, serverURL))

	return passed, failed
}

func createInviteHTTP(adminClient *http.Client, adminJWT, serverURL string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"role":               "member",
		"expires_in_seconds": 3600,
	})
	resp, err := authedPost(adminClient, adminJWT, serverURL+"/api/invites", body)
	if err != nil {
		return "", fmt.Errorf("create invite request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create invite status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode invite response: %w", err)
	}
	if result.Code == "" {
		return "", fmt.Errorf("empty invite code in response")
	}
	return result.Code, nil
}

func redeemInvite(
	handler *pair.PairingHandler,
	inviteCode, displayName string,
) (*ecdsa.PrivateKey, []byte, string, error) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&clientKey.PublicKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal pubkey: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "e2e-member-device"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, clientKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	pairReq := pair.PairRequest{
		DevicePublicKey: string(pubPEM),
		DeviceName:      "e2e-member-device",
		CSR:             string(csrPEM),
		Credential:      pair.PairCredential{Kind: "invite", Token: inviteCode},
		DisplayName:     displayName,
	}
	body, _ := json.Marshal(pairReq)

	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req := newRequest("POST", fmt.Sprintf("https://127.0.0.1:%d/api/pair", testPort), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := insecureClient.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("pair request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, nil, "", fmt.Errorf("pair status %d: %s", resp.StatusCode, respBody)
	}

	var pairResp pair.PairResponse
	if err := json.NewDecoder(resp.Body).Decode(&pairResp); err != nil {
		return nil, nil, "", fmt.Errorf("decode pair response: %w", err)
	}

	return clientKey, []byte(pairResp.ClientCert), pairResp.UserID, nil
}

func deleteUserHTTP(adminClient *http.Client, adminJWT, serverURL, userID string) error {
	req := newRequest("DELETE", serverURL+"/api/users/"+userID, nil)
	req.Header.Set("Authorization", "Bearer "+adminJWT)
	resp, err := adminClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete user request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete user status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

func expectForbidden(client *http.Client, jwt, url string) error {
	resp, err := authedGet(client, jwt, url)
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("expected 403, got %d", resp.StatusCode)
	}
	return nil
}

func expectCertRenewForbidden(memberHTTP *http.Client, memberKey *ecdsa.PrivateKey, memberCertPEM []byte, serverURL string) error {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "e2e-member-device"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, memberKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	req := newRequest("POST", serverURL+"/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := memberHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("renew request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected 403 for revoked device, got %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

func testSyncDashboardTypeAccepted(client *http.Client, jwt string) error {
	resp, err := authedGet(client, jwt, fmt.Sprintf("https://127.0.0.1:%d/api/sync/manifest", testPort))
	if err != nil {
		return fmt.Errorf("manifest request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("manifest status %d: %s", resp.StatusCode, respBody)
	}

	var manifest struct {
		Records []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}

	for _, r := range manifest.Records {
		if r.ID == "dash-e2e-1" && r.Type == "dashboard" {
			return nil
		}
	}
	return fmt.Errorf("dashboard record dash-e2e-1 not found in manifest")
}
