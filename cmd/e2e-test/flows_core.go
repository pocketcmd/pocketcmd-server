package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/server"
)

func coreFlow(srvComp testServerComponents, admin adminCredentials) (int, int) {
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

	mintInvite := func(role, target string) (string, error) {
		inv, err := srvComp.invites.Create(pki.CreateInviteParams{
			Role: role, ExpiresIn: time.Hour, TargetUserID: target, CreatedByUID: admin.userID,
		})
		if err != nil {
			return "", err
		}
		return inv.Code, nil
	}
	pairFresh := func(code, displayName, deviceName string) (*http.Client, string, string, string, error) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, certPEM, userID, err := pairWithInviteKey(key, code, displayName, deviceName)
		if err != nil {
			return nil, "", "", "", err
		}
		client, _, err := buildMTLSClient(key, certPEM)
		if err != nil {
			return nil, "", "", "", err
		}
		jwt, err := getSession(client, srvComp.registry)
		if err != nil {
			return nil, "", "", "", err
		}
		dev, ok := srvComp.registry.LookupByPublicKeyPEM(encodePubPEM(&key.PublicKey))
		if !ok {
			return nil, "", "", "", fmt.Errorf("paired device not in registry")
		}
		return client, jwt, userID, dev.DeviceID, nil
	}

	ownerCode, err := mintInvite("admin", admin.userID)
	if err != nil {
		check("Core: mint owner second-device invite", err)
		return passed, failed
	}
	ownerHTTP, ownerJWT, ownerUserID, ownerDeviceID, err := pairFresh(ownerCode, admin.displayName, "owner-core-device")
	if err != nil || ownerUserID != admin.userID {
		check("Core: owner pairs a fresh device", fmt.Errorf("err=%v user=%q", err, ownerUserID))
		return passed, failed
	}
	check("Core: owner pairs a fresh device", nil)

	check("Core: /api/health is 200 with status ok and every check ok", testHealthShape(serverURL))
	check("Core: /api/capabilities is exactly {version, api_version}", testCapabilitiesShape(serverURL, "e2e-test"))
	check("Core: authed route without the version header is 400 api_version_mismatch",
		testMissingVersionHeaderAuthed(ownerHTTP, ownerJWT, serverURL))

	memberCode, err := mintInvite("member", "")
	if err != nil {
		check("Core: mint member invite", err)
		return passed, failed
	}
	longKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _, _, err = pairWithInviteKey(longKey, memberCode, strings.Repeat("n", pki.MaxDisplayNameLen+1), "core-long-name")
	check("Core: pairing with an over-long display name is 400 display_name_too_long",
		expectPairError(err, "display_name_too_long"))
	_, _, _, err = pairWithInviteKey(longKey, memberCode, "Core Member", strings.Repeat("d", pki.MaxDeviceNameLen+1))
	check("Core: pairing with an over-long device name is 400 name_too_long",
		expectPairError(err, "name_too_long"))
	memHTTP, memJWT, memUserID, memDeviceA, err := pairFresh(memberCode, "Core Member", "core-member-a")
	check("Core: the invite survives the refused attempts and pairs the member", err)
	if err != nil {
		return passed, failed
	}

	codeB, err1 := mintInvite("member", memUserID)
	codeC, err2 := mintInvite("member", memUserID)
	if err1 != nil || err2 != nil {
		check("Core: mint second-device invites", errors.Join(err1, err2))
		return passed, failed
	}
	httpB, jwtB, _, memDeviceB, errB := pairFresh(codeB, "Core Member", "core-member-b")
	_, _, _, memDeviceC, errC := pairFresh(codeC, "Core Member", "core-member-c")
	check("Core: member pairs two more devices", errors.Join(errB, errC))
	if errB != nil || errC != nil {
		return passed, failed
	}

	check("Core: member lists only own devices with self first",
		listDevices(memHTTP, memJWT, serverURL, "", func(list []deviceObject) error {
			if len(list) != 3 || !list[0].Self || list[0].DeviceID != memDeviceA {
				return fmt.Errorf("unexpected listing %+v", list)
			}
			for _, d := range list {
				if d.UserID != memUserID || d.Status != "active" || (d.Self && d.DeviceID != memDeviceA) {
					return fmt.Errorf("foreign or non-active device in member listing: %+v", d)
				}
			}
			return nil
		}))
	check("Core: admin listing includes every active device",
		listDevices(ownerHTTP, ownerJWT, serverURL, "", func(list []deviceObject) error {
			if len(list) == 0 || !list[0].Self || list[0].DeviceID != ownerDeviceID {
				return fmt.Errorf("caller's device not first: %+v", list)
			}
			return expectDevices(list, map[string]string{
				ownerDeviceID: "active", memDeviceA: "active", memDeviceB: "active", memDeviceC: "active",
			}, false)
		}))

	check("Core: DELETE /api/devices/self from device B leaves",
		expectStatus(httpB, jwtB, "DELETE", serverURL+"/api/devices/self", nil, http.StatusOK))
	if _, err := getSession(httpB, srvComp.registry); err == nil {
		check("Core: a left device cannot open a session", fmt.Errorf("session issued to a left device"))
	} else {
		check("Core: a left device cannot open a session", nil)
	}
	check("Core: member cannot remove the owner's device (403 owner_required)",
		expectError(memHTTP, memJWT, "DELETE", serverURL+"/api/devices/"+ownerDeviceID, nil, http.StatusForbidden, "owner_required"))
	check("Core: unknown device is 404 device_not_found",
		expectError(ownerHTTP, ownerJWT, "DELETE", serverURL+"/api/devices/0000000000000000", nil, http.StatusNotFound, "device_not_found"))
	check("Core: admin revokes the member's device C",
		expectStatus(ownerHTTP, ownerJWT, "DELETE", serverURL+"/api/devices/"+memDeviceC, nil, http.StatusOK))
	check("Core: revoking it again is idempotent",
		expectStatus(ownerHTTP, ownerJWT, "DELETE", serverURL+"/api/devices/"+memDeviceC, nil, http.StatusOK))
	check("Core: default listing hides the left and the revoked device",
		listDevices(ownerHTTP, ownerJWT, serverURL, "", func(list []deviceObject) error {
			for _, d := range list {
				if d.DeviceID == memDeviceB || d.DeviceID == memDeviceC || d.Status != "active" || d.RemovedAt != nil {
					return fmt.Errorf("removed device in default listing: %+v", d)
				}
			}
			return nil
		}))
	check("Core: include=all lists left and revoked with removed_at",
		listDevices(ownerHTTP, ownerJWT, serverURL, "?include=all", func(list []deviceObject) error {
			return expectDevices(list, map[string]string{
				ownerDeviceID: "active", memDeviceA: "active", memDeviceB: "left", memDeviceC: "revoked",
			}, false)
		}))
	check("Core: member include=all is scoped to own devices",
		listDevices(memHTTP, memJWT, serverURL, "?include=all", func(list []deviceObject) error {
			if len(list) != 3 {
				return fmt.Errorf("expected the member's 3 devices, got %d", len(list))
			}
			for _, d := range list {
				if d.UserID != memUserID {
					return fmt.Errorf("foreign device %+v", d)
				}
			}
			return nil
		}))

	check("Core: owner transfers ownership to the member",
		expectTransfer(ownerHTTP, ownerJWT, serverURL, memUserID, http.StatusOK, ""))
	check("Core: the new owner's only device cannot leave (409 last_device)",
		expectError(memHTTP, memJWT, "DELETE", serverURL+"/api/devices/self", nil, http.StatusConflict, "last_device"))
	if d, _ := srvComp.registry.FindByID(memDeviceA); d == nil || d.Status != "active" {
		check("Core: the refused leave changed nothing", fmt.Errorf("device = %+v", d))
	} else {
		check("Core: the refused leave changed nothing", nil)
	}
	check("Core: the previous owner cannot transfer (403 owner_required)",
		expectTransfer(ownerHTTP, ownerJWT, serverURL, memUserID, http.StatusForbidden, "owner_required"))
	check("Core: self transfer is 400 self_transfer",
		expectTransfer(memHTTP, memJWT, serverURL, memUserID, http.StatusBadRequest, "self_transfer"))
	goneCode, err := mintInvite("member", "")
	if err != nil {
		check("Core: mint throwaway member invite", err)
		return passed, failed
	}
	_, _, goneUserID, _, err := pairFresh(goneCode, "Core Gone", "core-gone")
	check("Core: a throwaway member joins", err)
	if err == nil {
		check("Core: owner revokes the throwaway member",
			deleteUserHTTP(memHTTP, memJWT, serverURL, goneUserID))
		check("Core: transfer to a revoked user is 409 target_not_active",
			expectTransfer(memHTTP, memJWT, serverURL, goneUserID, http.StatusConflict, "target_not_active"))
	}
	check("Core: the member hands ownership back",
		expectTransfer(memHTTP, memJWT, serverURL, admin.userID, http.StatusOK, ""))
	check("Core: owner demotes the member back to member",
		patchUser(ownerHTTP, ownerJWT, serverURL, memUserID, map[string]string{"role": "member"}, http.StatusOK, ""))

	reqPassed, reqFailed := metricRequestFlow(ownerHTTP, ownerJWT, admin.userID, memHTTP, memJWT, memUserID, serverURL)
	passed += reqPassed
	failed += reqFailed

	check("Core: GET /api/server/status reports version, uptime and counts",
		testServerStatus(ownerHTTP, ownerJWT, serverURL))
	check("Core: member is refused on /api/server/status",
		expectStatus(memHTTP, memJWT, "GET", serverURL+"/api/server/status", nil, http.StatusForbidden))
	check("Core: GET /api/server/config is exactly {service_mode}",
		testServerConfigShape(ownerHTTP, ownerJWT, serverURL))
	check("Core: member is refused on /api/server/config",
		expectStatus(memHTTP, memJWT, "GET", serverURL+"/api/server/config", nil, http.StatusForbidden))
	check("Core: nothing in /api/server/config is writable (PATCH is 405)",
		expectStatus(ownerHTTP, ownerJWT, "PATCH", serverURL+"/api/server/config", []byte(`{"push_enabled":false}`), http.StatusMethodNotAllowed))
	cfgPath := config.ConfigFilePath()
	origCfg, readErr := os.ReadFile(cfgPath)
	if err := os.WriteFile(cfgPath, []byte("{not json"), 0600); err != nil {
		check("Core: plant an unreadable config.json", err)
	} else {
		check("Core: unreadable config.json is 500 config_unreadable on GET",
			expectError(ownerHTTP, ownerJWT, "GET", serverURL+"/api/server/config", nil, http.StatusInternalServerError, "config_unreadable"))
		if readErr == nil {
			err = os.WriteFile(cfgPath, origCfg, 0600)
		} else {
			err = os.Remove(cfgPath)
		}
		if err != nil {
			check("Core: restore config.json", err)
		}
		check("Core: config.json is served again once readable",
			testServerConfigShape(ownerHTTP, ownerJWT, serverURL))
	}

	auditPassed, auditFailed := auditFeedFlow(ownerHTTP, ownerJWT, memHTTP, memJWT, serverURL)
	passed += auditPassed
	failed += auditFailed

	logsPassed, logsFailed := logFeedFlow(ownerHTTP, ownerJWT, memHTTP, memJWT, memUserID, serverURL)
	passed += logsPassed
	failed += logsFailed

	check("Core: GET /api/host-keys returns the fingerprints list", testHostKeys(memHTTP, memJWT, serverURL))

	const vault = "e2e-vault-core"
	vaultPost := func(client *http.Client, jwt, path string, payload map[string]string) error {
		body, _ := json.Marshal(payload)
		return expectStatus(client, jwt, "POST", serverURL+path, body, http.StatusNoContent)
	}
	check("Core: owner creates the guard vault",
		expectStatus(ownerHTTP, ownerJWT, "POST", serverURL+"/api/vault/create", []byte(`{"vault_id":"`+vault+`"}`), http.StatusOK))
	check("Core: owner grants the member manage",
		vaultPost(ownerHTTP, ownerJWT, "/api/vault/grant", map[string]string{"vault_id": vault, "user_id": memUserID, "level": "manage"}))
	check("Core: revoking the owner's vault access is 409 cannot_revoke_owner",
		expectError(memHTTP, memJWT, "POST", serverURL+"/api/vault/revoke",
			[]byte(`{"vault_id":"`+vault+`","user_id":"`+admin.userID+`"}`), http.StatusConflict, "cannot_revoke_owner"))
	check("Core: owner lowers own level to view (another manager exists)",
		vaultPost(ownerHTTP, ownerJWT, "/api/vault/grant", map[string]string{"vault_id": vault, "user_id": admin.userID, "level": "view"}))
	check("Core: revoking the last manager is 409 last_manager",
		expectError(memHTTP, memJWT, "POST", serverURL+"/api/vault/revoke",
			[]byte(`{"vault_id":"`+vault+`","user_id":"`+memUserID+`"}`), http.StatusConflict, "last_manager"))
	check("Core: demoting the last manager is 409 last_manager",
		expectError(memHTTP, memJWT, "POST", serverURL+"/api/vault/grant",
			[]byte(`{"vault_id":"`+vault+`","user_id":"`+memUserID+`","level":"edit"}`), http.StatusConflict, "last_manager"))

	sshPassed, sshFailed := sshOneShotFlow(srvComp, ownerHTTP, ownerJWT, ownerDeviceID, memHTTP, memJWT, serverURL)
	passed += sshPassed
	failed += sshFailed

	return passed, failed
}

func expectDevices(list []deviceObject, want map[string]string, exact bool) error {
	seen := map[string]bool{}
	for _, d := range list {
		status, known := want[d.DeviceID]
		if !known {
			if exact {
				return fmt.Errorf("unexpected device %+v", d)
			}
			continue
		}
		seen[d.DeviceID] = true
		if d.Status != status {
			return fmt.Errorf("device %s: status %q, want %q", d.DeviceID, d.Status, status)
		}
		if status == "active" && d.RemovedAt != nil {
			return fmt.Errorf("active device %s carries removed_at", d.DeviceID)
		}
		if status != "active" && (d.RemovedAt == nil || *d.RemovedAt == "") {
			return fmt.Errorf("%s device %s lacks removed_at", status, d.DeviceID)
		}
	}
	for id := range want {
		if !seen[id] {
			return fmt.Errorf("device %s missing from listing", id)
		}
	}
	return nil
}

func expectError(client *http.Client, jwt, method, url string, body []byte, wantStatus int, wantErr string) error {
	status, respBody, err := doJSON(client, jwt, method, url, body)
	if err != nil {
		return err
	}
	if status != wantStatus {
		return fmt.Errorf("status %d (want %d): %s", status, wantStatus, respBody)
	}
	return expectErrorCode(respBody, wantErr)
}

func getObject(client *http.Client, jwt, url string) (map[string]any, error) {
	status, body, err := doJSON(client, jwt, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", status, body)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("decode: %w (%s)", err, body)
	}
	return obj, nil
}

func testHealthShape(serverURL string) error {
	resp, err := insecureGet(serverURL + "/api/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if body.Status != "ok" {
		return fmt.Errorf("status %q", body.Status)
	}
	for _, k := range []string{"devices", "tls", "db"} {
		if body.Checks[k] != "ok" {
			return fmt.Errorf("check %s = %q (%v)", k, body.Checks[k], body.Checks)
		}
	}
	if len(body.Checks) != 3 {
		return fmt.Errorf("unexpected checks %v", body.Checks)
	}
	return nil
}

func testCapabilitiesShape(serverURL, wantVersion string) error {
	resp, err := insecureGet(serverURL + "/api/capabilities")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var caps map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(caps) != 2 || caps["version"] != wantVersion || caps["api_version"] != server.APIVersion {
		return fmt.Errorf("capabilities = %v, want exactly {version:%q, api_version:%q}", caps, wantVersion, server.APIVersion)
	}
	return nil
}

func testMissingVersionHeaderAuthed(client *http.Client, jwt, serverURL string) error {
	req, _ := http.NewRequest("GET", serverURL+"/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body struct {
		Error            string `json:"error"`
		ServerAPIVersion string `json:"server_api_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if resp.StatusCode != http.StatusBadRequest || body.Error != "api_version_mismatch" || body.ServerAPIVersion != server.APIVersion {
		return fmt.Errorf("status %d body %+v", resp.StatusCode, body)
	}
	return nil
}

func metricRequestFlow(ownerHTTP *http.Client, ownerJWT, ownerUserID string, memHTTP *http.Client, memJWT, memUserID, serverURL string) (int, int) {
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
	base := serverURL + "/api/metrics/requests"

	type request struct {
		ID               string `json:"id"`
		Label            string `json:"label"`
		Command          string `json:"command"`
		IntervalOverride *int   `json:"interval_override"`
		RequestedBy      string `json:"requested_by"`
		CreatedAt        string `json:"created_at"`
		Status           string `json:"status"`
		DecidedBy        string `json:"decided_by"`
		DecidedAt        string `json:"decided_at"`
	}
	create := func(client *http.Client, jwt, body string) (request, error) {
		status, respBody, err := doJSON(client, jwt, "POST", base, []byte(body))
		if err != nil {
			return request{}, err
		}
		if status != http.StatusOK {
			return request{}, fmt.Errorf("status %d: %s", status, respBody)
		}
		var r request
		if err := json.Unmarshal(respBody, &r); err != nil {
			return request{}, fmt.Errorf("decode: %w (%s)", err, respBody)
		}
		return r, nil
	}
	decide := func(client *http.Client, jwt, id, verb string, wantStatus int, wantErr string) (request, error) {
		status, respBody, err := doJSON(client, jwt, "POST", base+"/"+id+"/"+verb, nil)
		if err != nil {
			return request{}, err
		}
		if status != wantStatus {
			return request{}, fmt.Errorf("status %d (want %d): %s", status, wantStatus, respBody)
		}
		if wantErr != "" {
			return request{}, expectErrorCode(respBody, wantErr)
		}
		var r request
		if err := json.Unmarshal(respBody, &r); err != nil {
			return request{}, fmt.Errorf("decode: %w (%s)", err, respBody)
		}
		return r, nil
	}
	list := func(client *http.Client, jwt string) ([]request, error) {
		status, respBody, err := doJSON(client, jwt, "GET", base, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("status %d: %s", status, respBody)
		}
		var all []request
		if err := json.Unmarshal(respBody, &all); err != nil {
			return nil, fmt.Errorf("decode: %w (%s)", err, respBody)
		}
		return all, nil
	}
	ids := func(all []request) map[string]request {
		m := map[string]request{}
		for _, r := range all {
			m[r.ID] = r
		}
		return m
	}

	reqA, err := create(memHTTP, memJWT, `{"label":"Core approve me","command":"echo 42","interval_override":60}`)
	if err == nil {
		switch {
		case !strings.HasPrefix(reqA.ID, "req-"), reqA.Status != "pending", reqA.RequestedBy != memUserID,
			reqA.Label != "Core approve me", reqA.Command != "echo 42", reqA.IntervalOverride == nil || *reqA.IntervalOverride != 60,
			reqA.CreatedAt == "", reqA.DecidedBy != "", reqA.DecidedAt != "":
			err = fmt.Errorf("unexpected request object %+v", reqA)
		}
	}
	check("Core: member files a metric request (pending, attributed)", err)
	if err != nil {
		return passed, failed
	}
	reqB, errB := create(memHTTP, memJWT, `{"label":"Core decline me","command":"echo 1"}`)
	reqC, errC := create(memHTTP, memJWT, `{"label":"Core withdraw me","command":"echo 2"}`)
	check("Core: member files two more requests", errors.Join(errB, errC))
	if errB != nil || errC != nil {
		return passed, failed
	}
	if reqB.IntervalOverride != nil {
		check("Core: interval_override is null when omitted", fmt.Errorf("got %v", *reqB.IntervalOverride))
	} else {
		check("Core: interval_override is null when omitted", nil)
	}

	check("Core: empty label is 400 invalid_request",
		expectError(memHTTP, memJWT, "POST", base, []byte(`{"label":"","command":"echo 1"}`), http.StatusBadRequest, "invalid_request"))
	check("Core: interval outside 5–21600 s is 400 invalid_request",
		expectError(memHTTP, memJWT, "POST", base, []byte(`{"label":"x","command":"echo 1","interval_override":1}`), http.StatusBadRequest, "invalid_request"))
	check("Core: over-long label is 400 invalid_request",
		expectError(memHTTP, memJWT, "POST", base, []byte(`{"label":"`+strings.Repeat("l", 121)+`","command":"echo 1"}`), http.StatusBadRequest, "invalid_request"))
	check("Core: malformed request body is 400 invalid_body",
		expectError(memHTTP, memJWT, "POST", base, []byte(`{`), http.StatusBadRequest, "invalid_body"))

	own, err := list(memHTTP, memJWT)
	if err == nil {
		m := ids(own)
		for _, r := range own {
			if r.RequestedBy != memUserID {
				err = fmt.Errorf("foreign request in member listing: %+v", r)
			}
		}
		if _, ok := m[reqA.ID]; !ok || len(m) < 3 {
			err = fmt.Errorf("member listing misses own requests: %+v", own)
		}
	}
	check("Core: member lists only own requests", err)
	all, err := list(ownerHTTP, ownerJWT)
	if err == nil {
		m := ids(all)
		if _, ok := m[reqA.ID]; !ok {
			err = fmt.Errorf("owner listing misses %s: %+v", reqA.ID, all)
		}
	}
	check("Core: owner lists every request", err)

	_, err = decide(memHTTP, memJWT, reqA.ID, "approve", http.StatusForbidden, "permission_required")
	check("Core: member without metrics.commands.create cannot approve (403 permission_required)", err)
	_, err = decide(memHTTP, memJWT, reqB.ID, "decline", http.StatusForbidden, "permission_required")
	check("Core: member without metrics.commands.create cannot decline (403 permission_required)", err)

	approved, err := decide(ownerHTTP, ownerJWT, reqA.ID, "approve", http.StatusOK, "")
	if err == nil && (approved.Status != "approved" || approved.DecidedBy != ownerUserID || approved.DecidedAt == "") {
		err = fmt.Errorf("unexpected decided object %+v", approved)
	}
	check("Core: owner approves request A", err)
	_, err = decide(ownerHTTP, ownerJWT, reqA.ID, "approve", http.StatusConflict, "already_decided")
	check("Core: approving again is 409 already_decided", err)
	declined, err := decide(ownerHTTP, ownerJWT, reqB.ID, "decline", http.StatusOK, "")
	if err == nil && (declined.Status != "declined" || declined.DecidedBy != ownerUserID) {
		err = fmt.Errorf("unexpected decided object %+v", declined)
	}
	check("Core: owner declines request B", err)
	_, err = decide(ownerHTTP, ownerJWT, reqA.ID, "decline", http.StatusConflict, "already_decided")
	check("Core: declining a decided request is 409 already_decided", err)
	_, err = decide(ownerHTTP, ownerJWT, "req-0000000000000000", "approve", http.StatusNotFound, "request_not_found")
	check("Core: approving an unknown request is 404 request_not_found", err)
	_, err = decide(ownerHTTP, ownerJWT, "req-0000000000000000", "decline", http.StatusNotFound, "request_not_found")
	check("Core: declining an unknown request is 404 request_not_found", err)

	check("Core: member cannot delete an approved request (403 permission_required)",
		expectError(memHTTP, memJWT, "DELETE", base+"/"+reqA.ID, nil, http.StatusForbidden, "permission_required"))
	check("Core: member cannot delete a declined request (403 permission_required)",
		expectError(memHTTP, memJWT, "DELETE", base+"/"+reqB.ID, nil, http.StatusForbidden, "permission_required"))
	check("Core: unknown id is 403 permission_required for a member (unprobeable)",
		expectError(memHTTP, memJWT, "DELETE", base+"/req-0000000000000000", nil, http.StatusForbidden, "permission_required"))
	check("Core: member withdraws own pending request C",
		expectStatus(memHTTP, memJWT, "DELETE", base+"/"+reqC.ID, nil, http.StatusOK))
	check("Core: owner deletes the approved request (revokes the command)",
		expectStatus(ownerHTTP, ownerJWT, "DELETE", base+"/"+reqA.ID, nil, http.StatusOK))
	check("Core: deleting it again is 404 request_not_found",
		expectError(ownerHTTP, ownerJWT, "DELETE", base+"/"+reqA.ID, nil, http.StatusNotFound, "request_not_found"))
	all, err = list(ownerHTTP, ownerJWT)
	if err == nil {
		m := ids(all)
		_, hasA := m[reqA.ID]
		_, hasC := m[reqC.ID]
		if hasA || hasC || m[reqB.ID].Status != "declined" {
			err = fmt.Errorf("listing after deletes: %+v", all)
		}
	}
	check("Core: listing reflects the deletes and the declined request", err)
	return passed, failed
}

func testServerStatus(client *http.Client, jwt, serverURL string) error {
	st, err := getObject(client, jwt, serverURL+"/api/server/status")
	if err != nil {
		return err
	}
	for _, k := range []string{"version", "started_at", "uptime_seconds", "state_dir_bytes", "active_devices", "total_devices", "active_users"} {
		if _, ok := st[k]; !ok {
			return fmt.Errorf("missing %s in %v", k, st)
		}
	}
	if st["version"] != "e2e-test" {
		return fmt.Errorf("version %v", st["version"])
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(st["started_at"])); err != nil {
		return fmt.Errorf("started_at: %w", err)
	}
	num := func(k string) float64 { v, _ := st[k].(float64); return v }
	if num("uptime_seconds") < 0 || num("state_dir_bytes") <= 0 {
		return fmt.Errorf("uptime/state size: %v", st)
	}
	if num("active_devices") < 2 || num("total_devices") < num("active_devices")+2 || num("active_users") < 2 {
		return fmt.Errorf("counts: %v", st)
	}
	return nil
}

func testServerConfigShape(client *http.Client, jwt, serverURL string) error {
	cfg, err := getObject(client, jwt, serverURL+"/api/server/config")
	if err != nil {
		return err
	}
	mode, _ := cfg["service_mode"].(string)
	if len(cfg) != 1 || (mode != "background" && mode != "foreground") {
		return fmt.Errorf("config = %v", cfg)
	}
	return nil
}

type feedPage struct {
	Entries      []map[string]any `json:"entries"`
	Total        int              `json:"total"`
	NextBeforeID *int64           `json:"next_before_id"`
}

func getFeed(client *http.Client, jwt, url string) (feedPage, error) {
	status, body, err := doJSON(client, jwt, "GET", url, nil)
	if err != nil {
		return feedPage{}, err
	}
	if status != http.StatusOK {
		return feedPage{}, fmt.Errorf("status %d: %s", status, body)
	}
	var page feedPage
	if err := json.Unmarshal(body, &page); err != nil {
		return feedPage{}, fmt.Errorf("decode: %w (%s)", err, body)
	}
	if page.Entries == nil {
		return feedPage{}, fmt.Errorf("entries must be an array, not null: %s", body)
	}
	return page, nil
}

func auditFeedFlow(ownerHTTP *http.Client, ownerJWT string, memHTTP *http.Client, memJWT, serverURL string) (int, int) {
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
	base := serverURL + "/api/audit"

	full, err := getFeed(ownerHTTP, ownerJWT, base)
	if err == nil {
		switch {
		case full.Total == 0 || len(full.Entries) == 0 || len(full.Entries) > 50:
			err = fmt.Errorf("total=%d entries=%d", full.Total, len(full.Entries))
		case full.Entries[0]["msg"] == nil || full.Entries[0]["time"] == nil:
			err = fmt.Errorf("entry lacks msg/time: %v", full.Entries[0])
		default:
			first, _ := full.Entries[0]["time"].(string)
			last, _ := full.Entries[len(full.Entries)-1]["time"].(string)
			if first < last {
				err = fmt.Errorf("not newest first: %s before %s", first, last)
			}
		}
	}
	check("Core: GET /api/audit returns the newest entries first", err)
	if err != nil {
		return passed, failed
	}
	msgs := map[string]bool{}
	for _, e := range full.Entries {
		msg, _ := e["msg"].(string)
		msgs[msg] = true
	}
	for _, want := range []string{"device_registered", "owner_transferred", "device_revoked", "device_left", "metric_request_approved"} {
		if !msgs[want] {
			err = fmt.Errorf("audit event %s missing from the newest %d entries", want, len(full.Entries))
			break
		}
	}
	check("Core: audit feed carries this run's events", err)

	one, err := getFeed(ownerHTTP, ownerJWT, base+"?limit=1")
	if err == nil && (len(one.Entries) != 1 || one.Total < full.Total) {
		err = fmt.Errorf("limit=1: entries=%d total=%d (full %d)", len(one.Entries), one.Total, full.Total)
	}
	check("Core: audit limit=1 returns one entry with the full total", err)
	second, err := getFeed(ownerHTTP, ownerJWT, base+"?limit=1&offset=1")
	if err == nil {
		a, _ := json.Marshal(one.Entries[0])
		b, _ := json.Marshal(second.Entries[0])
		if len(second.Entries) != 1 || bytes.Equal(a, b) {
			err = fmt.Errorf("offset=1 returned the same entry: %s", b)
		}
	}
	check("Core: audit offset pages past the newest entry", err)
	ranged, err := getFeed(ownerHTTP, ownerJWT, base+"?from=2000-01-01T00:00:00Z&to=3000-01-01T00:00:00Z")
	if err == nil && ranged.Total < full.Total {
		err = fmt.Errorf("total %d < %d", ranged.Total, full.Total)
	}
	check("Core: audit from/to spanning everything keeps the total", err)
	future, err := getFeed(ownerHTTP, ownerJWT, base+"?from=2999-01-01T00:00:00Z")
	if err == nil && (future.Total != 0 || len(future.Entries) != 0) {
		err = fmt.Errorf("future window returned %d entries", future.Total)
	}
	check("Core: audit from in the future returns nothing", err)
	check("Core: audit malformed from is 400 invalid_time",
		expectError(ownerHTTP, ownerJWT, "GET", base+"?from=yesterday", nil, http.StatusBadRequest, "invalid_time"))
	check("Core: audit year out of range is 400 invalid_time",
		expectError(ownerHTTP, ownerJWT, "GET", base+"?to=1999-12-31T00:00:00Z", nil, http.StatusBadRequest, "invalid_time"))
	check("Core: audit from after to is 400 invalid_time_range",
		expectError(ownerHTTP, ownerJWT, "GET", base+"?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", nil, http.StatusBadRequest, "invalid_time_range"))
	check("Core: member is refused on /api/audit (403 owner_required)",
		expectError(memHTTP, memJWT, "GET", base, nil, http.StatusForbidden, "owner_required"))
	return passed, failed
}

func logFeedFlow(ownerHTTP *http.Client, ownerJWT string, memHTTP *http.Client, memJWT, memUserID, serverURL string) (int, int) {
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
	base := serverURL + "/api/logs"
	// Give the log store's writer goroutine a moment to land the entries.
	time.Sleep(200 * time.Millisecond)

	entryIDs := func(page feedPage) ([]int64, error) {
		out := make([]int64, 0, len(page.Entries))
		for _, e := range page.Entries {
			id, ok := e["id"].(float64)
			if !ok || e["msg"] == nil {
				return nil, fmt.Errorf("entry lacks id/msg: %v", e)
			}
			out = append(out, int64(id))
		}
		return out, nil
	}

	full, err := getFeed(ownerHTTP, ownerJWT, base)
	var ids []int64
	if err == nil {
		ids, err = entryIDs(full)
	}
	if err == nil {
		if full.Total == 0 || len(ids) == 0 || len(ids) > 50 {
			err = fmt.Errorf("total=%d entries=%d", full.Total, len(ids))
		} else if !sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i] > ids[j] }) {
			err = fmt.Errorf("ids not descending: %v", ids)
		}
	}
	check("Core: GET /api/logs returns request entries newest first", err)
	if err != nil {
		return passed, failed
	}

	one, err := getFeed(ownerHTTP, ownerJWT, base+"?limit=1")
	var oneIDs []int64
	if err == nil {
		oneIDs, err = entryIDs(one)
	}
	if err == nil && (len(oneIDs) != 1 || one.NextBeforeID == nil || *one.NextBeforeID != oneIDs[0]) {
		err = fmt.Errorf("limit=1: ids=%v next_before_id=%v", oneIDs, one.NextBeforeID)
	}
	check("Core: logs limit=1 yields a next_before_id cursor", err)
	if err == nil {
		older, err := getFeed(ownerHTTP, ownerJWT, fmt.Sprintf("%s?limit=5&before_id=%d", base, *one.NextBeforeID))
		var olderIDs []int64
		if err == nil {
			olderIDs, err = entryIDs(older)
		}
		if err == nil {
			if len(olderIDs) == 0 {
				err = fmt.Errorf("no older page")
			}
			for _, id := range olderIDs {
				if id >= *one.NextBeforeID {
					err = fmt.Errorf("id %d not older than cursor %d", id, *one.NextBeforeID)
				}
			}
		}
		check("Core: logs before_id pages to strictly older entries", err)
	}
	byUser, err := getFeed(ownerHTTP, ownerJWT, base+"?user_id="+memUserID)
	if err == nil {
		if byUser.Total == 0 || len(byUser.Entries) == 0 {
			err = fmt.Errorf("no entries for %s", memUserID)
		}
		for _, e := range byUser.Entries {
			if e["user_id"] != memUserID {
				err = fmt.Errorf("foreign entry in user filter: %v", e)
				break
			}
		}
	}
	check("Core: logs user_id filter returns only that member's entries", err)
	ranged, err := getFeed(ownerHTTP, ownerJWT, base+"?from=2000-01-01T00:00:00Z&to=3000-01-01T00:00:00Z")
	if err == nil && ranged.Total == 0 {
		err = fmt.Errorf("empty within an all-spanning window")
	}
	check("Core: logs from/to spanning everything returns entries", err)
	future, err := getFeed(ownerHTTP, ownerJWT, base+"?from=2999-01-01T00:00:00Z")
	if err == nil && (future.Total != 0 || len(future.Entries) != 0 || future.NextBeforeID != nil) {
		err = fmt.Errorf("future window returned %d entries", future.Total)
	}
	check("Core: logs from in the future returns nothing", err)
	check("Core: logs malformed to is 400 invalid_time",
		expectError(ownerHTTP, ownerJWT, "GET", base+"?to=soon", nil, http.StatusBadRequest, "invalid_time"))
	check("Core: logs from after to is 400 invalid_time_range",
		expectError(ownerHTTP, ownerJWT, "GET", base+"?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", nil, http.StatusBadRequest, "invalid_time_range"))
	check("Core: member is refused on /api/logs (403 owner_required)",
		expectError(memHTTP, memJWT, "GET", base, nil, http.StatusForbidden, "owner_required"))
	return passed, failed
}

func testHostKeys(client *http.Client, jwt, serverURL string) error {
	status, body, err := doJSON(client, jwt, "GET", serverURL+"/api/host-keys", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, body)
	}
	var resp struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode: %w (%s)", err, body)
	}
	if !bytes.Contains(body, []byte(`"fingerprints"`)) {
		return fmt.Errorf("fingerprints key missing: %s", body)
	}
	for _, fp := range resp.Fingerprints {
		if len(fp) != 43 || strings.HasPrefix(fp, "SHA256:") || strings.ContainsAny(fp, "= \n") {
			return fmt.Errorf("fingerprint %q is not an unpadded base64 sha256", fp)
		}
	}
	return nil
}

func sshOneShotFlow(srvComp testServerComponents, ownerHTTP *http.Client, ownerJWT, ownerDeviceID string, memHTTP *http.Client, memJWT, serverURL string) (int, int) {
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

	home, err := os.UserHomeDir()
	if err != nil {
		check("Core: resolve test HOME", err)
		return passed, failed
	}
	sshDir := filepath.Join(home, ".ssh")
	keyPath := filepath.Join(sshDir, "id_e2e")
	err = os.MkdirAll(sshDir, 0700)
	if err == nil {
		err = os.WriteFile(keyPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ne2e\n-----END OPENSSH PRIVATE KEY-----\n"), 0600)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(sshDir, "config"), []byte(
			"Host core-e2e\n  HostName 10.0.0.9\n  User e2e\n  Port 2222\n  IdentityFile "+keyPath+"\n"), 0600)
	}
	check("Core: seed ~/.ssh/config under the test HOME", err)
	if err != nil {
		return passed, failed
	}

	fetched := make(chan string, 1)
	srvComp.srv.OnSSHConfigsFetch(func(deviceID string) {
		select {
		case fetched <- deviceID:
		default:
		}
	})
	srvComp.srv.EnableSSHOneShot()

	check("Core: member is refused on /api/ssh-configs before the gate is consumed",
		expectForbidden(memHTTP, memJWT, serverURL+"/api/ssh-configs"))

	status, body, err := doJSON(ownerHTTP, ownerJWT, "GET", serverURL+"/api/ssh-configs", nil)
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("status %d: %s", status, body)
	}
	var export struct {
		Hosts []struct {
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
			Username string `json:"username"`
			Port     int    `json:"port"`
			KeyRef   string `json:"key_ref"`
		} `json:"hosts"`
		Keys []struct {
			Path      string `json:"path"`
			Content   string `json:"content"`
			Encrypted bool   `json:"encrypted"`
		} `json:"keys"`
	}
	if err == nil {
		if err = json.Unmarshal(body, &export); err != nil {
			err = fmt.Errorf("decode: %w (%s)", err, body)
		}
	}
	if err == nil {
		switch {
		case len(export.Hosts) != 1 || export.Hosts[0].Name != "core-e2e" || export.Hosts[0].Hostname != "10.0.0.9" ||
			export.Hosts[0].Username != "e2e" || export.Hosts[0].Port != 2222 || export.Hosts[0].KeyRef != keyPath:
			err = fmt.Errorf("hosts = %+v", export.Hosts)
		case len(export.Keys) != 1 || export.Keys[0].Path != keyPath || !strings.Contains(export.Keys[0].Content, "OPENSSH PRIVATE KEY") || export.Keys[0].Encrypted:
			err = fmt.Errorf("keys = %+v", export.Keys)
		}
	}
	check("Core: the first /api/ssh-configs fetch exports the seeded host and key", err)

	select {
	case id := <-fetched:
		if id != ownerDeviceID {
			check("Core: the fetch callback names the fetching device", fmt.Errorf("got %q want %q", id, ownerDeviceID))
		} else {
			check("Core: the fetch callback names the fetching device", nil)
		}
	case <-time.After(2 * time.Second):
		check("Core: the fetch callback names the fetching device", fmt.Errorf("callback never fired"))
	}

	check("Core: a second fetch is 409 already_fetched",
		expectError(ownerHTTP, ownerJWT, "GET", serverURL+"/api/ssh-configs", nil, http.StatusConflict, "already_fetched"))

	page, err := getFeed(ownerHTTP, ownerJWT, serverURL+"/api/audit?limit=10")
	if err == nil {
		err = fmt.Errorf("no ssh_configs_export entry in the newest 10 audit entries")
		for _, e := range page.Entries {
			if e["msg"] == "ssh_configs_export" && e["device_id"] == ownerDeviceID && e["host_count"] == float64(1) && e["key_count"] == float64(1) {
				err = nil
				break
			}
		}
	}
	check("Core: the export is audited with the device and counts", err)
	return passed, failed
}
