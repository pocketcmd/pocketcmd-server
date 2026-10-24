package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/pair"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/push"
	"github.com/pocketcmd/pocketcmd-server/internal/server"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func extendedFlow(srvComp testServerComponents, admin adminCredentials) (int, int) {
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

	adminHTTP, _, err := buildMTLSClient(admin.key, admin.certPEM)
	if err != nil {
		check("Ext: admin mTLS client", err)
		return passed, failed
	}

	check("Ext: /api/config returns pollIntervalMs", testAPIConfig(serverURL))
	check("Ext: /api/capabilities returns api_version 1.0", testCapabilities(serverURL))
	check("Ext: missing/wrong API version header is rejected", testAPIVersionRejected(serverURL))

	newCertPEM, err := renewCertMTLS(adminHTTP, admin.key, serverURL)
	check("Ext: cert renew via mTLS", err)
	if err == nil {
		renewedHTTP, _, cliErr := buildMTLSClient(admin.key, newCertPEM)
		if cliErr == nil {
			_, cliErr = getSession(renewedHTTP, srvComp.registry)
		}
		check("Ext: renewed cert opens a session", cliErr)
	}
	check("Ext: cert renew via signed challenge",
		renewCertViaChallenge(admin.key, srvComp.serverFP, serverURL))

	revokableCode, err := createInviteHTTP(adminHTTP, admin.jwt, serverURL)
	check("Ext: create invite for revocation test", err)
	if err == nil {
		check("Ext: GET /api/invites lists the invite",
			expectInviteListed(adminHTTP, admin.jwt, serverURL, revokableCode))
		check("Ext: DELETE /api/invites/{code} revokes",
			revokeInviteHTTP(adminHTTP, admin.jwt, serverURL, revokableCode))
		_, _, _, redeemErr := redeemInvite(srvComp.pairHandler, revokableCode, "Should Fail")
		check("Ext: redeeming a revoked invite fails",
			expectPairError(redeemErr, "invite_revoked"))
	}

	pinnedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		check("Ext: generate pinned key", err)
		return passed, failed
	}
	pinnedFP, err := pki.PubKeyFingerprint(encodePubPEM(&pinnedKey.PublicKey))
	if err != nil {
		check("Ext: pinned key fingerprint", err)
		return passed, failed
	}
	pinnedCode, err := createInviteFull(adminHTTP, admin.jwt, serverURL, map[string]interface{}{
		"role":               "member",
		"expires_in_seconds": 3600,
		"pinned_fingerprint": pinnedFP,
		"label":              "pinned e2e",
	})
	check("Ext: create pinned invite", err)
	if err == nil {
		wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, _, _, wrongErr := pairWithInviteKey(wrongKey, pinnedCode, "Wrong Device", "wrong-device")
		check("Ext: pinned invite rejects mismatched device",
			expectPairError(wrongErr, "device_pin_mismatch"))

		_, _, _, rightErr := pairWithInviteKey(pinnedKey, pinnedCode, "Pinned Member", "pinned-device")
		check("Ext: pinned invite accepts pinned device", rightErr)
	}

	memberCode, err := createInviteHTTP(adminHTTP, admin.jwt, serverURL)
	if err != nil {
		check("Ext: create invite for member2", err)
		return passed, failed
	}
	member2Key, member2CertPEM, member2UserID, err := redeemInvite(srvComp.pairHandler, memberCode, "E2E Member2")
	check("Ext: member2 redeems invite", err)
	if err != nil {
		return passed, failed
	}
	member2HTTP, _, err := buildMTLSClient(member2Key, member2CertPEM)
	if err != nil {
		check("Ext: member2 mTLS client", err)
		return passed, failed
	}
	member2JWT, err := getSession(member2HTTP, srvComp.registry)
	check("Ext: member2 JWT session", err)
	if err != nil {
		return passed, failed
	}

	check("Ext: member can list users",
		expectUserListed(member2HTTP, member2JWT, serverURL, member2UserID, "member"))
	check("Ext: admin appears in user list with role admin",
		expectUserListed(adminHTTP, admin.jwt, serverURL, admin.userID, "admin"))

	check("Ext: member renames self",
		patchUser(member2HTTP, member2JWT, serverURL, member2UserID,
			map[string]string{"display_name": "E2E Member2 Renamed"}, http.StatusOK, ""))
	check("Ext: member cannot change roles",
		patchUser(member2HTTP, member2JWT, serverURL, member2UserID,
			map[string]string{"role": "admin"}, http.StatusForbidden, ""))
	check("Ext: demoting the owner returns 409 owner_immutable",
		patchUser(adminHTTP, admin.jwt, serverURL, admin.userID,
			map[string]string{"role": "member"}, http.StatusConflict, "owner_immutable"))
	check("Ext: admin promotes member2",
		patchUser(adminHTTP, admin.jwt, serverURL, member2UserID,
			map[string]string{"role": "admin"}, http.StatusOK, ""))
	check("Ext: admin demotes member2 back",
		patchUser(adminHTTP, admin.jwt, serverURL, member2UserID,
			map[string]string{"role": "member"}, http.StatusOK, ""))

	forCode, err := createInviteFull(adminHTTP, admin.jwt, serverURL, map[string]interface{}{
		"expires_in_seconds": 3600,
		"target_user_id":     member2UserID,
	})
	check("Ext: create --for invite targeting member2", err)
	if err == nil {
		secondKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, _, secondUserID, forErr := pairWithInviteKey(secondKey, forCode, "E2E Member2", "member2-tablet")
		check("Ext: --for invite pairs second device", forErr)
		if forErr == nil {
			if secondUserID != member2UserID {
				check("Ext: --for device joins existing user",
					fmt.Errorf("got user %q want %q", secondUserID, member2UserID))
			} else {
				check("Ext: --for device joins existing user", nil)
			}
			devs, devErr := srvComp.registry.DevicesByUserID(member2UserID)
			if devErr != nil {
				check("Ext: member2 device count = 2", devErr)
			} else if len(devs) != 2 {
				check("Ext: member2 device count = 2", fmt.Errorf("got %d", len(devs)))
			} else {
				check("Ext: member2 device count = 2", nil)
			}
		}
	}

	pushPassed, pushFailed := pushFlow(adminHTTP, admin, serverURL)
	passed += pushPassed
	failed += pushFailed

	return passed, failed
}

func testAPIConfig(serverURL string) error {
	resp, err := insecureGet(serverURL + "/api/config")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var cfg struct {
		PollIntervalMs int `json:"pollIntervalMs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if cfg.PollIntervalMs <= 0 {
		return fmt.Errorf("pollIntervalMs missing or zero")
	}
	return nil
}

func testCapabilities(serverURL string) error {
	resp, err := insecureGet(serverURL + "/api/capabilities")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var caps struct {
		APIVersion string `json:"api_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if caps.APIVersion != "1.0" {
		return fmt.Errorf("api_version %q, want 1.0", caps.APIVersion)
	}
	return nil
}

func testAPIVersionRejected(serverURL string) error {
	client := insecureHTTPClient()
	for _, header := range []string{"", "0.9", "2.0"} {
		req, _ := http.NewRequest("GET", serverURL+"/api/config", nil)
		if header != "" {
			req.Header.Set(server.APIVersionHeader, header)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		var body struct {
			Error            string `json:"error"`
			ServerAPIVersion string `json:"server_api_version"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("header %q: status %d, want 400", header, resp.StatusCode)
		}
		if decodeErr != nil || body.Error != "api_version_mismatch" || body.ServerAPIVersion != server.APIVersion {
			return fmt.Errorf("header %q: unexpected body %+v (%v)", header, body, decodeErr)
		}
	}
	req, _ := http.NewRequest("GET", serverURL+"/api/config", nil)
	req.Header.Set(server.APIVersionHeader, "1.9")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("same major, other minor: status %d, want 200", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", serverURL+"/api/capabilities", nil)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("capabilities without header: status %d, want 200", resp.StatusCode)
	}
	return nil
}

func renewCertMTLS(client *http.Client, key *ecdsa.PrivateKey, serverURL string) ([]byte, error) {
	csrPEM, err := makeCSR(key, "e2e-test-device")
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	req := newRequest("POST", serverURL+"/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	var result struct {
		Cert      string `json:"cert"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if result.Cert == "" || result.ExpiresAt == "" {
		return nil, fmt.Errorf("cert or expires_at missing in response")
	}
	return []byte(result.Cert), nil
}

func renewCertViaChallenge(key *ecdsa.PrivateKey, serverFP, serverURL string) error {
	pubPEM := encodePubPEM(&key.PublicKey)

	challengeBody, _ := json.Marshal(map[string]string{"public_key": pubPEM})
	resp, err := insecurePost(serverURL+"/api/cert/challenge", challengeBody)
	if err != nil {
		return fmt.Errorf("challenge request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("challenge status %d: %s", resp.StatusCode, respBody)
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		return fmt.Errorf("decode challenge: %w", err)
	}
	if len(challenge.Nonce) != 64 {
		return fmt.Errorf("nonce length %d, want 64", len(challenge.Nonce))
	}

	digest := sha256.Sum256([]byte(challenge.Nonce + ":" + serverFP))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return fmt.Errorf("sign challenge: %w", err)
	}

	csrPEM, err := makeCSR(key, "e2e-test-device")
	if err != nil {
		return err
	}
	renewBody, _ := json.Marshal(map[string]string{
		"csr":              string(csrPEM),
		"signed_challenge": base64.StdEncoding.EncodeToString(sig),
		"public_key":       pubPEM,
		"nonce":            challenge.Nonce,
	})
	renewResp, err := insecurePost(serverURL+"/api/cert/renew", renewBody)
	if err != nil {
		return fmt.Errorf("renew request: %w", err)
	}
	defer renewResp.Body.Close()
	if renewResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(renewResp.Body)
		return fmt.Errorf("renew status %d: %s", renewResp.StatusCode, respBody)
	}
	var result struct {
		Cert string `json:"cert"`
	}
	if err := json.NewDecoder(renewResp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode renew: %w", err)
	}
	if result.Cert == "" {
		return fmt.Errorf("empty cert in challenge renew response")
	}
	return nil
}

func createInviteFull(client *http.Client, jwt, serverURL string, params map[string]interface{}) (string, error) {
	body, _ := json.Marshal(params)
	resp, err := authedPost(client, jwt, serverURL+"/api/invites", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	var result struct {
		Code  string `json:"code"`
		QRURL string `json:"qr_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if result.Code == "" {
		return "", fmt.Errorf("empty code")
	}
	if result.QRURL == "" {
		return "", fmt.Errorf("empty qr_url")
	}
	return result.Code, nil
}

func expectInviteListed(client *http.Client, jwt, serverURL, code string) error {
	resp, err := authedGet(client, jwt, serverURL+"/api/invites")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	var invites []struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&invites); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	for _, inv := range invites {
		if inv.Code == code {
			return nil
		}
	}
	return fmt.Errorf("invite %s not in list of %d invites", code[:8], len(invites))
}

func revokeInviteHTTP(client *http.Client, jwt, serverURL, code string) error {
	req := newRequest("DELETE", serverURL+"/api/invites/"+code, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

func patchUser(client *http.Client, jwt, serverURL, userID string, body map[string]string, wantStatus int, wantErrCode string) error {
	payload, _ := json.Marshal(body)
	req := newRequest("PATCH", serverURL+"/api/users/"+userID, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("status %d (want %d): %s", resp.StatusCode, wantStatus, respBody)
	}
	if wantErrCode != "" {
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return fmt.Errorf("decode error body: %w (%s)", err, respBody)
		}
		if errResp.Error != wantErrCode {
			return fmt.Errorf("error code %q, want %q", errResp.Error, wantErrCode)
		}
	}
	return nil
}

func expectUserListed(client *http.Client, jwt, serverURL, userID, wantRole string) error {
	resp, err := authedGet(client, jwt, serverURL+"/api/users")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	var users []struct {
		UserID      string `json:"user_id"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		DeviceCount int    `json:"device_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	for _, u := range users {
		if u.UserID == userID {
			if u.Role != wantRole {
				return fmt.Errorf("role %q, want %q", u.Role, wantRole)
			}
			if u.DeviceCount < 1 {
				return fmt.Errorf("device_count %d, want >= 1", u.DeviceCount)
			}
			return nil
		}
	}
	return fmt.Errorf("user %s not in list of %d users", userID, len(users))
}

func pairWithInviteKey(clientKey *ecdsa.PrivateKey, inviteCode, displayName, deviceName string) (*ecdsa.PrivateKey, []byte, string, error) {
	pubPEM := encodePubPEM(&clientKey.PublicKey)
	csrPEM, err := makeCSR(clientKey, deviceName)
	if err != nil {
		return nil, nil, "", err
	}

	pairReq := pair.PairRequest{
		DevicePublicKey: pubPEM,
		DeviceName:      deviceName,
		CSR:             string(csrPEM),
		Credential:      pair.PairCredential{Kind: "invite", Token: inviteCode},
		DisplayName:     displayName,
	}
	body, _ := json.Marshal(pairReq)

	resp, err := insecurePost(fmt.Sprintf("https://127.0.0.1:%d/api/pair", testPort), body)
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

func expectPairError(err error, wantCode string) error {
	if err == nil {
		return fmt.Errorf("expected pair error %q, got success", wantCode)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(wantCode)) {
		return fmt.Errorf("expected error code %q in %q", wantCode, err.Error())
	}
	return nil
}

func pushFlow(adminHTTP *http.Client, admin adminCredentials, serverURL string) (int, int) {
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

	db, err := state.Open(config.PocketCmdDir())
	if err != nil {
		check("Push: open state.db", err)
		return passed, failed
	}
	pushStore := push.NewStore(db)
	expiresAt := time.Now().Add(time.Hour).UnixMilli()

	register := func(deviceID, token string) error {
		payload := map[string]interface{}{
			"device_token": token,
			"platform":     "android",
			"signed_token": "e2e-signed",
			"expires_at":   expiresAt,
		}
		if deviceID != "" {
			payload["device_id"] = deviceID
		}
		body, _ := json.Marshal(payload)
		resp, err := authedPost(adminHTTP, admin.jwt, serverURL+"/api/push/register", body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
		}
		var out map[string]any
		if err := json.Unmarshal(respBody, &out); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		if out["status"] != "ok" || len(out) != 1 {
			return fmt.Errorf("want exactly {\"status\":\"ok\"}, got %s", respBody)
		}
		return nil
	}

	writeRegistration := func(deviceID, token string) error {
		if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, display_name, role, created_at)
			VALUES ('e2e-dead-user', 'dead', 'member', '2026-01-01T00:00:00Z')`); err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT OR IGNORE INTO devices (device_id, public_key, user_id, paired_at)
			VALUES (?, 'e2e-fake-pem', 'e2e-dead-user', '2026-01-01T00:00:00Z')`, deviceID); err != nil {
			return err
		}
		return pushStore.Upsert(push.PushRegistration{
			DeviceID: deviceID, DeviceToken: token,
			Platform: "android", SignedToken: "e2e-signed", ExpiresAt: expiresAt,
		})
	}

	check("Push: register own device (live token)", register("", "tok-live"))
	check("Push: register rejects foreign device_id", func() error {
		err := register("e2e-other-device", "tok-x")
		if err == nil {
			return fmt.Errorf("expected 403 for foreign device_id")
		}
		return nil
	}())
	check("Push: register rejects traversal device_id", func() error {
		err := register("../evil", "tok-x")
		if err == nil {
			return fmt.Errorf("expected rejection for path-traversal device_id")
		}
		return nil
	}())
	check("Push: seed dead-device registration", writeRegistration("e2e-dead-device", "tok-dead"))

	regs, err := pushStore.ReadAll()
	if err != nil {
		check("Push: read registrations", err)
		return passed, failed
	}
	if len(regs) < 2 {
		check("Push: read registrations", fmt.Errorf("expected >= 2 registrations, got %d", len(regs)))
		return passed, failed
	}
	check("Push: read registrations", nil)

	var notified []map[string]interface{}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/notify" {
			w.WriteHeader(404)
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_body"}`))
			return
		}
		if body["v"] != float64(2) || body["title"] == nil || body["body"] == nil {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"unsupported_version"}`))
			return
		}
		notified = append(notified, body)
		if body["device_token"] == "tok-dead" {
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":"token_gone"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer relay.Close()

	client := push.NewPushClient(relay.URL)
	gone, err := client.Notify(regs, push.Notification{
		SignalType: "metric_alert",
		Title:      "CPU Alert (e2e)",
		Body:       "CPU at 99.0 (threshold: 90.0)",
		Sound:      "default",
		Data:       map[string]string{"metric_id": "custom:req-e2e", "value": "99.00"},
	})
	check("Push: notify via relay v2", err)
	if len(notified) < 2 {
		check("Push: relay received both notifies", fmt.Errorf("got %d", len(notified)))
	} else {
		check("Push: relay received both notifies", nil)
	}

	foundDead := false
	for _, id := range gone {
		if id == "e2e-dead-device" {
			foundDead = true
		}
	}
	if !foundDead {
		check("Push: dead token reported gone", fmt.Errorf("gone=%v", gone))
	} else {
		check("Push: dead token reported gone", nil)
	}

	for _, id := range gone {
		if err := pushStore.Remove(id); err != nil {
			check("Push: prune dead registration", err)
			return passed, failed
		}
	}
	after, _ := pushStore.ReadAll()
	for _, reg := range after {
		if reg.DeviceID == "e2e-dead-device" {
			check("Push: prune dead registration", fmt.Errorf("dead registration still on disk"))
			return passed, failed
		}
	}
	check("Push: prune dead registration", nil)

	return passed, failed
}

func encodePubPEM(pub *ecdsa.PublicKey) string {
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func makeCSR(key *ecdsa.PrivateKey, cn string) ([]byte, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func insecureHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func insecureGet(url string) (*http.Response, error) {
	return insecureHTTPClient().Do(newRequest("GET", url, nil))
}

func insecurePost(url string, body []byte) (*http.Response, error) {
	req := newRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return insecureHTTPClient().Do(req)
}
