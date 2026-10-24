package main

import (
	"encoding/json"
	"fmt"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"io"
	"net/http"
	"time"
)

func vaultFlow(srvComp testServerComponents, admin adminCredentials) (int, int) {
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
	const (
		vaultA = "e2e-vault-a"
		vaultB = "e2e-vault-b"
	)

	adminHTTP, _, err := buildMTLSClient(admin.key, admin.certPEM)
	if err != nil {
		check("Vault: admin mTLS client", err)
		return passed, failed
	}

	code, err := createInviteHTTP(adminHTTP, admin.jwt, serverURL)
	if err != nil {
		check("Vault: create invite for vault member", err)
		return passed, failed
	}
	memKey, memCertPEM, memUserID, err := redeemInvite(srvComp.pairHandler, code, "E2E VaultMember")
	check("Vault: member joins", err)
	if err != nil {
		return passed, failed
	}
	memHTTP, _, err := buildMTLSClient(memKey, memCertPEM)
	if err != nil {
		check("Vault: member mTLS client", err)
		return passed, failed
	}
	memJWT, err := getSession(memHTTP, srvComp.registry)
	check("Vault: member JWT session", err)
	if err != nil {
		return passed, failed
	}

	var wrapID string

	vaultPost := func(client *http.Client, jwt, path string, payload map[string]interface{}) (int, []byte, error) {
		body, _ := json.Marshal(payload)
		resp, err := authedPost(client, jwt, serverURL+path, body)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, respBody, nil
	}

	expectErrCode := func(status int, body []byte, wantStatus int, wantCode string) error {
		if status != wantStatus {
			return fmt.Errorf("expected status %d, got %d: %s", wantStatus, status, body)
		}
		var e struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &e); err != nil {
			return fmt.Errorf("decode error body: %w (%s)", err, body)
		}
		if e.Error != wantCode {
			return fmt.Errorf("expected error %q, got %q", wantCode, e.Error)
		}
		return nil
	}

	type syncRec struct {
		ID      string          `json:"id"`
		Type    string          `json:"type"`
		Deleted bool            `json:"deleted"`
		VaultID string          `json:"vault_id"`
		Data    json.RawMessage `json:"data"`
	}

	pushOne := func(client *http.Client, jwt, id, recType, vaultID string, ts int64, deleted bool, data string) (bool, error) {
		record := map[string]interface{}{
			"id":             id,
			"type":           recType,
			"schema_version": 1,
			"updated_at":     ts,
			"device_id":      "e2e-vault",
			"deleted":        deleted,
			"data":           json.RawMessage(data),
		}
		if vaultID != "" {
			record["vault_id"] = vaultID
		}
		body, _ := json.Marshal(map[string]interface{}{"records": []map[string]interface{}{record}})
		resp, err := authedPost(client, jwt, serverURL+"/api/sync/push", body)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			respBody, _ := io.ReadAll(resp.Body)
			return false, fmt.Errorf("push status %d: %s", resp.StatusCode, respBody)
		}
		var result struct {
			Accepted []string                  `json:"accepted"`
			Rejected []datasync.RejectedRecord `json:"rejected"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, fmt.Errorf("decode push result: %w", err)
		}
		for _, a := range result.Accepted {
			if a == id {
				return true, nil
			}
		}
		for _, r := range result.Rejected {
			if r.ID == id {
				return false, nil
			}
		}
		return false, fmt.Errorf("record %s in neither accepted nor rejected: %+v", id, result)
	}
	expectAccepted := func(client *http.Client, jwt, id, recType, vaultID string, ts int64, deleted bool, data string) error {
		ok, err := pushOne(client, jwt, id, recType, vaultID, ts, deleted, data)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("record %s was rejected, expected accepted", id)
		}
		return nil
	}
	expectRejected := func(client *http.Client, jwt, id, recType, vaultID string, ts int64, deleted bool, data string) error {
		ok, err := pushOne(client, jwt, id, recType, vaultID, ts, deleted, data)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("record %s was accepted, expected rejected", id)
		}
		return nil
	}

	pullOne := func(client *http.Client, jwt, id string) (*syncRec, error) {
		body, _ := json.Marshal(map[string][]string{"ids": {id}})
		resp, err := authedPost(client, jwt, serverURL+"/api/sync/pull", body)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			respBody, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("pull status %d: %s", resp.StatusCode, respBody)
		}
		var result struct {
			Records []syncRec `json:"records"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("decode pull result: %w", err)
		}
		if len(result.Records) == 0 {
			return nil, nil
		}
		return &result.Records[0], nil
	}

	manifestIDs := func(client *http.Client, jwt string) (map[string]bool, error) {
		resp, err := authedGet(client, jwt, serverURL+"/api/sync/manifest")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			respBody, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("manifest status %d: %s", resp.StatusCode, respBody)
		}
		var manifest struct {
			Records []struct {
				ID string `json:"id"`
			} `json:"records"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
			return nil, err
		}
		ids := map[string]bool{}
		for _, r := range manifest.Records {
			ids[r.ID] = true
		}
		return ids, nil
	}

	membersLevel := func(client *http.Client, jwt, vaultID, userID string) (string, error) {
		resp, err := authedGet(client, jwt, serverURL+"/api/vault/members?vault_id="+vaultID)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			respBody, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("members status %d: %s", resp.StatusCode, respBody)
		}
		var result struct {
			Members []struct {
				UserID string `json:"user_id"`
				Level  string `json:"level"`
			} `json:"members"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", fmt.Errorf("decode members: %w", err)
		}
		for _, m := range result.Members {
			if m.UserID == userID {
				return m.Level, nil
			}
		}
		return "", nil
	}

	ts := time.Now().UnixMilli()

	status, body, err := vaultPost(memHTTP, memJWT, "/api/vault/create",
		map[string]interface{}{"vault_id": vaultA})
	if err != nil {
		check("Vault: member cannot create vault", err)
	} else {
		check("Vault: member cannot create vault",
			expectErrCode(status, body, http.StatusForbidden, "owner_or_admin_required"))
	}

	status, body, err = vaultPost(adminHTTP, admin.jwt, "/api/vault/create",
		map[string]interface{}{"vault_id": vaultA})
	if err != nil || status != 200 {
		check("Vault: owner creates vault A", fmt.Errorf("err=%v status=%d body=%s", err, status, body))
		return passed, failed
	}
	var createResp struct {
		VaultID string `json:"vault_id"`
	}
	if jsonErr := json.Unmarshal(body, &createResp); jsonErr != nil || createResp.VaultID != vaultA {
		check("Vault: owner creates vault A", fmt.Errorf("unexpected body %s (err=%v)", body, jsonErr))
	} else {
		check("Vault: owner creates vault A", nil)
	}

	status, body, err = vaultPost(adminHTTP, admin.jwt, "/api/vault/create",
		map[string]interface{}{"vault_id": vaultA})
	if err != nil {
		check("Vault: duplicate create conflicts", err)
	} else {
		check("Vault: duplicate create conflicts",
			expectErrCode(status, body, http.StatusConflict, "vault_exists"))
	}

	status, body, err = vaultPost(adminHTTP, admin.jwt, "/api/vault/create",
		map[string]interface{}{"vault_id": vaultB})
	if err != nil || status != 200 {
		check("Vault: owner creates vault B", fmt.Errorf("err=%v status=%d body=%s", err, status, body))
	} else {
		check("Vault: owner creates vault B", nil)
	}

	check("Vault: vault_identity rejected as unsupported",
		expectRejected(memHTTP, memJWT, "vident-e2e-member", "vault_identity", "", ts,
			false, `{"public_key":"legacy"}`))

	memDevices, devErr := srvComp.registry.DevicesByUserID(memUserID)
	if devErr != nil || len(memDevices) == 0 {
		check("Vault: resolve member device id",
			fmt.Errorf("devices for member: err=%v count=%d", devErr, len(memDevices)))
		return passed, failed
	}
	memDeviceID := memDevices[0].DeviceID
	wrapID = vaultA + ":" + memDeviceID
	const memPubKey = "e2e-member-device-vault-pubkey"
	check("Vault: member pushes device_vault_key",
		expectAccepted(memHTTP, memJWT, memDeviceID, "device_vault_key", "", ts,
			false, `{"device_id":"`+memDeviceID+`","dvk_pub":"`+memPubKey+`","kind":"p256",`+
				`"mtls_spki":"e2e-spki","backing":"software","sig":"e2e-sig",`+
				`"attestation":{"status":"unverified"},"created_at":`+fmt.Sprint(ts)+`,"version":2}`))

	adminDevices, devErr := srvComp.registry.DevicesByUserID(admin.userID)
	if devErr != nil || len(adminDevices) == 0 {
		check("Vault: resolve admin device id",
			fmt.Errorf("devices for admin: err=%v count=%d", devErr, len(adminDevices)))
	} else {
		check("Vault: member cannot squat admin device_vault_key",
			expectRejected(memHTTP, memJWT, adminDevices[0].DeviceID, "device_vault_key", "", ts,
				false, `{"dvk_pub":"attacker","kind":"p256"}`))
	}

	pubkeysErr := func() error {
		resp, err := authedGet(memHTTP, memJWT, serverURL+"/api/vault/pubkeys")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("pubkeys status %d: %s", resp.StatusCode, respBody)
		}
		var result struct {
			Identities []json.RawMessage `json:"identities"`
			Devices    []struct {
				DeviceID    string          `json:"device_id"`
				UserID      string          `json:"user_id"`
				DisplayName string          `json:"display_name"`
				DvkPub      string          `json:"dvk_pub"`
				Kind        string          `json:"kind"`
				Sig         string          `json:"sig"`
				Attestation json.RawMessage `json:"attestation"`
			} `json:"devices"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decode pubkeys: %w", err)
		}
		if result.Identities != nil {
			return fmt.Errorf("legacy identities field must be absent, got %d entries", len(result.Identities))
		}
		for _, d := range result.Devices {
			if d.DeviceID == memDeviceID {
				if d.UserID != memUserID {
					return fmt.Errorf("expected user_id %q, got %q", memUserID, d.UserID)
				}
				if d.DvkPub != memPubKey {
					return fmt.Errorf("expected dvk_pub %q, got %q", memPubKey, d.DvkPub)
				}
				if d.Sig != "e2e-sig" {
					return fmt.Errorf("expected sig e2e-sig, got %q", d.Sig)
				}
				var att map[string]any
				if err := json.Unmarshal(d.Attestation, &att); err != nil || att["status"] != "unverified" {
					return fmt.Errorf("attestation object not passed through: %s", d.Attestation)
				}
				if d.DisplayName != "E2E VaultMember" {
					return fmt.Errorf("expected display_name 'E2E VaultMember', got %q", d.DisplayName)
				}
				if d.Kind != "p256" {
					return fmt.Errorf("expected kind p256, got %q", d.Kind)
				}
				return nil
			}
		}
		return fmt.Errorf("member device missing from directory: %+v", result.Devices)
	}()
	check("Vault: pubkeys directory lists member device", pubkeysErr)

	check("Vault: owner pushes wrap for member",
		expectAccepted(adminHTTP, admin.jwt, wrapID, "vault_wrap", vaultA, ts+1,
			false, `{"recipient_device":"`+memDeviceID+`","wrapped_key":"e2e-wrapped-vault-key"}`))

	if ids, err := manifestIDs(memHTTP, memJWT); err != nil {
		check("Vault: wrap withheld from ungranted member", err)
	} else if ids[wrapID] {
		check("Vault: wrap withheld from ungranted member",
			fmt.Errorf("%s reached a member with no grant on the vault", wrapID))
	} else {
		check("Vault: wrap withheld from ungranted member", nil)
	}

	status, body, err = vaultPost(adminHTTP, admin.jwt, "/api/vault/grant",
		map[string]interface{}{"vault_id": vaultA, "user_id": memUserID, "level": "view"})
	if err != nil {
		check("Vault: owner grants member view", err)
	} else if status != http.StatusNoContent {
		check("Vault: owner grants member view", fmt.Errorf("expected 204, got %d: %s", status, body))
	} else {
		check("Vault: owner grants member view", nil)
	}

	if ids, err := manifestIDs(memHTTP, memJWT); err != nil {
		check("Vault: wrap in member manifest after grant", err)
	} else if !ids[wrapID] {
		check("Vault: wrap in member manifest after grant",
			fmt.Errorf("%s missing from granted member's manifest", wrapID))
	} else {
		check("Vault: wrap in member manifest after grant", nil)
	}

	if rec, err := pullOne(memHTTP, memJWT, wrapID); err != nil {
		check("Vault: member pulls wrap after grant", err)
	} else if rec == nil {
		check("Vault: member pulls wrap after grant", fmt.Errorf("wrap not visible to recipient"))
	} else if rec.Type != "vault_wrap" || rec.Deleted {
		check("Vault: member pulls wrap after grant",
			fmt.Errorf("unexpected record type=%s deleted=%v", rec.Type, rec.Deleted))
	} else {
		var d struct {
			RecipientDevice string `json:"recipient_device"`
		}
		if json.Unmarshal(rec.Data, &d) != nil || d.RecipientDevice != memDeviceID {
			check("Vault: member pulls wrap after grant",
				fmt.Errorf("wrap data recipient mismatch: %s", rec.Data))
		} else {
			check("Vault: member pulls wrap after grant", nil)
		}
	}

	if level, err := membersLevel(memHTTP, memJWT, vaultA, memUserID); err != nil {
		check("Vault: members list shows member with view", err)
	} else if level != "view" {
		check("Vault: members list shows member with view", fmt.Errorf("expected view, got %q", level))
	} else {
		check("Vault: members list shows member with view", nil)
	}
	if level, err := membersLevel(memHTTP, memJWT, vaultA, admin.userID); err != nil {
		check("Vault: members list shows owner with manage", err)
	} else if level != "manage" {
		check("Vault: members list shows owner with manage", fmt.Errorf("expected manage, got %q", level))
	} else {
		check("Vault: members list shows owner with manage", nil)
	}

	check("Vault: view member cannot push team-vault record",
		expectRejected(memHTTP, memJWT, "vsec-e2e-1", "secret_item", vaultA, ts+2,
			false, `{"ciphertext":"e2e-secret-v1"}`))

	status, body, err = vaultPost(adminHTTP, admin.jwt, "/api/vault/grant",
		map[string]interface{}{"vault_id": vaultA, "user_id": memUserID, "level": "edit"})
	if err != nil {
		check("Vault: owner re-grants member edit", err)
	} else if status != http.StatusNoContent {
		check("Vault: owner re-grants member edit", fmt.Errorf("expected 204, got %d: %s", status, body))
	} else {
		check("Vault: owner re-grants member edit", nil)
	}

	check("Vault: edit member push accepted",
		expectAccepted(memHTTP, memJWT, "vsec-e2e-1", "secret_item", vaultA, ts+3,
			false, `{"ciphertext":"e2e-secret-v1"}`))

	if ids, err := manifestIDs(memHTTP, memJWT); err != nil {
		check("Vault: member manifest sees team-vault record", err)
	} else if !ids["vsec-e2e-1"] {
		check("Vault: member manifest sees team-vault record", fmt.Errorf("vsec-e2e-1 missing"))
	} else {
		check("Vault: member manifest sees team-vault record", nil)
	}

	status, body, err = vaultPost(adminHTTP, admin.jwt, "/api/vault/revoke",
		map[string]interface{}{"vault_id": vaultA, "user_id": memUserID})
	if err != nil {
		check("Vault: owner revokes member", err)
	} else if status != http.StatusNoContent {
		check("Vault: owner revokes member", fmt.Errorf("expected 204, got %d: %s", status, body))
	} else {
		check("Vault: owner revokes member", nil)
	}

	if level, err := membersLevel(adminHTTP, admin.jwt, vaultA, memUserID); err != nil {
		check("Vault: revoked member gone from members list", err)
	} else if level != "" {
		check("Vault: revoked member gone from members list", fmt.Errorf("still listed with level %q", level))
	} else {
		check("Vault: revoked member gone from members list", nil)
	}

	if rec, err := pullOne(adminHTTP, admin.jwt, wrapID); err != nil {
		check("Vault: wrap tombstoned after revoke", err)
	} else if rec == nil {
		check("Vault: wrap tombstoned after revoke", fmt.Errorf("wrap record vanished instead of tombstoning"))
	} else if !rec.Deleted {
		check("Vault: wrap tombstoned after revoke", fmt.Errorf("wrap still live: %+v", rec))
	} else {
		check("Vault: wrap tombstoned after revoke", nil)
	}

	// The revoked member must still see the tombstone so its devices drop the wrap.
	if rec, err := pullOne(memHTTP, memJWT, wrapID); err != nil {
		check("Vault: revoked member receives wrap tombstone", err)
	} else if rec == nil {
		check("Vault: revoked member receives wrap tombstone",
			fmt.Errorf("tombstone not visible to revoked recipient"))
	} else if !rec.Deleted {
		check("Vault: revoked member receives wrap tombstone",
			fmt.Errorf("expected tombstone, got live record"))
	} else {
		check("Vault: revoked member receives wrap tombstone", nil)
	}

	if ids, err := manifestIDs(memHTTP, memJWT); err != nil {
		check("Vault: revoked member loses team-vault visibility", err)
	} else if ids["vsec-e2e-1"] {
		check("Vault: revoked member loses team-vault visibility",
			fmt.Errorf("vsec-e2e-1 still in revoked member's manifest"))
	} else {
		check("Vault: revoked member loses team-vault visibility", nil)
	}

	check("Vault: revoked member push rejected",
		expectRejected(memHTTP, memJWT, "vsec-e2e-1", "secret_item", vaultA, ts+4,
			false, `{"ciphertext":"e2e-secret-v2"}`))

	membersReq := newRequest("GET", serverURL+"/api/vault/members?vault_id="+vaultA, nil)
	membersReq.Header.Set("Authorization", "Bearer "+memJWT)
	if resp, err := memHTTP.Do(membersReq); err != nil {
		check("Vault: revoked member blocked from members list", err)
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		check("Vault: revoked member blocked from members list",
			expectErrCode(resp.StatusCode, respBody, http.StatusForbidden, "forbidden"))
	}

	check("Vault: live record pushed in vault A",
		expectAccepted(adminHTTP, admin.jwt, "vmove-e2e-1", "snippet", vaultA, ts+5,
			false, `{"ciphertext":"move-me"}`))

	check("Vault: in-place vault change of live record rejected",
		expectRejected(adminHTTP, admin.jwt, "vmove-e2e-1", "snippet", vaultB, ts+6,
			false, `{"ciphertext":"move-me"}`))

	check("Vault: tombstone in vault A accepted",
		expectAccepted(adminHTTP, admin.jwt, "vmove-e2e-1", "snippet", vaultA, ts+7,
			true, `{}`))

	check("Vault: re-create in vault B accepted",
		expectAccepted(adminHTTP, admin.jwt, "vmove-e2e-1", "snippet", vaultB, ts+8,
			false, `{"ciphertext":"move-me"}`))

	return passed, failed
}
