package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"io"
	"net/http"
	"time"
)

func pullRecordData(client *http.Client, jwt, serverURL, id string) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{"ids": []string{id}})
	resp, err := authedPost(client, jwt, serverURL+"/api/sync/pull", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Records []struct {
			Data json.RawMessage `json:"data"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Records) != 1 {
		return nil, fmt.Errorf("expected 1 record for %q, got %d", id, len(result.Records))
	}
	return result.Records[0].Data, nil
}

func syncScopingFlow(srvComp testServerComponents, admin adminCredentials) (int, int) {
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
		check("Sync: admin mTLS client", err)
		return passed, failed
	}

	code, err := createInviteHTTP(adminHTTP, admin.jwt, serverURL)
	if err != nil {
		check("Sync: create invite for member3", err)
		return passed, failed
	}
	m3Key, m3CertPEM, m3UserID, err := redeemInvite(srvComp.pairHandler, code, "E2E Member3")
	check("Sync: member3 joins", err)
	if err != nil {
		return passed, failed
	}
	m3HTTP, _, err := buildMTLSClient(m3Key, m3CertPEM)
	if err != nil {
		check("Sync: member3 mTLS client", err)
		return passed, failed
	}
	m3JWT, err := getSession(m3HTTP, srvComp.registry)
	check("Sync: member3 JWT session", err)
	if err != nil {
		return passed, failed
	}

	pushRecord := func(client *http.Client, jwt, id, recType string) error {
		body, _ := json.Marshal(map[string]interface{}{
			"records": []map[string]interface{}{{
				"id":             id,
				"type":           recType,
				"schema_version": 1,
				"updated_at":     time.Now().UnixMilli(),
				"device_id":      "e2e-sync",
				"deleted":        false,
				"data":           json.RawMessage(`{"scoped":true}`),
			}},
		})
		resp, err := authedPost(client, jwt, serverURL+"/api/sync/push", body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var result struct {
			Accepted []string                  `json:"accepted"`
			Rejected []datasync.RejectedRecord `json:"rejected"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}
		if len(result.Accepted) != 1 {
			return fmt.Errorf("record not accepted: %+v", result)
		}
		return nil
	}
	manifestIDs := func(client *http.Client, jwt string) (map[string]bool, error) {
		resp, err := authedGet(client, jwt, serverURL+"/api/sync/manifest")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
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

	check("Sync: member3 pushes a private record",
		pushRecord(m3HTTP, m3JWT, "m3-private", "task"))

	pushMonitoring := func(client *http.Client, jwt string) error {
		cur, err := pullRecordData(adminHTTP, admin.jwt, serverURL, "monitoring_config")
		if err != nil {
			return fmt.Errorf("pull current config: %w", err)
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(cur, &cfg); err != nil {
			return fmt.Errorf("decode config: %w", err)
		}
		interval, _ := cfg["default_interval_seconds"].(float64)
		cfg["default_interval_seconds"] = int(interval) + 1
		data, _ := json.Marshal(cfg)
		body, _ := json.Marshal(map[string]interface{}{
			"records": []map[string]interface{}{{
				"id":             "monitoring_config",
				"type":           "monitoring_config",
				"schema_version": 1,
				"updated_at":     time.Now().UnixMilli(),
				"device_id":      "e2e-sync",
				"deleted":        false,
				"data":           json.RawMessage(data),
			}},
		})
		resp, err := authedPost(client, jwt, serverURL+"/api/sync/push", body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var result struct {
			Accepted []string                  `json:"accepted"`
			Rejected []datasync.RejectedRecord `json:"rejected"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}
		if len(result.Accepted) != 1 {
			return fmt.Errorf("record not accepted: %+v", result)
		}
		return nil
	}

	if err := pushMonitoring(m3HTTP, m3JWT); err == nil {
		check("Sync: ungranted member cannot push monitoring_config",
			fmt.Errorf("expected rejection, but record was accepted"))
	} else {
		check("Sync: ungranted member cannot push monitoring_config", nil)
	}
	grantBody := []byte(`{"permissions":{
		"metrics.commands.read":{"granted":true},
		"metrics.commands.create":{"granted":true},
		"metrics.commands.update":{"granted":true},
		"metrics.read":{"granted":true},
		"alerts.read":{"granted":true},
		"sshkeys.sync":{"granted":true},
		"invites.device":{"granted":true}}}`)
	grantReq := newRequest("PATCH", serverURL+"/api/users/"+m3UserID, bytes.NewReader(grantBody))
	grantReq.Header.Set("Authorization", "Bearer "+admin.jwt)
	grantReq.Header.Set("Content-Type", "application/json")
	if grantResp, grantErr := adminHTTP.Do(grantReq); grantErr != nil {
		check("Sync: owner grants metrics.commands.create", grantErr)
	} else {
		respBody, _ := io.ReadAll(grantResp.Body)
		grantResp.Body.Close()
		if grantResp.StatusCode != http.StatusOK {
			check("Sync: owner grants metrics.commands.create",
				fmt.Errorf("status %d: %s", grantResp.StatusCode, respBody))
		} else {
			check("Sync: owner grants metrics.commands.create", nil)
		}
	}
	check("Sync: granted member pushes team-scoped monitoring_config",
		pushMonitoring(m3HTTP, m3JWT))

	adminIDs, err := manifestIDs(adminHTTP, admin.jwt)
	if err != nil {
		check("Sync: admin manifest", err)
		return passed, failed
	}
	if adminIDs["m3-private"] {
		check("Sync: admin cannot see member3's private record", fmt.Errorf("m3-private leaked into admin manifest"))
	} else {
		check("Sync: admin cannot see member3's private record", nil)
	}
	if !adminIDs["monitoring_config"] {
		check("Sync: admin sees team-scoped monitoring_config", fmt.Errorf("monitoring_config missing from admin manifest"))
	} else {
		check("Sync: admin sees team-scoped monitoring_config", nil)
	}

	m3IDs, err := manifestIDs(m3HTTP, m3JWT)
	if err != nil {
		check("Sync: member3 manifest", err)
		return passed, failed
	}
	if !m3IDs["m3-private"] {
		check("Sync: member3 sees own record", fmt.Errorf("m3-private missing from own manifest"))
	} else {
		check("Sync: member3 sees own record", nil)
	}
	if m3IDs["dash-e2e-1"] {
		check("Sync: member3 cannot see admin's record", fmt.Errorf("admin's dash-e2e-1 leaked into member manifest"))
	} else {
		check("Sync: member3 cannot see admin's record", nil)
	}

	pullBody, _ := json.Marshal(map[string][]string{"ids": {"m3-private"}})
	resp, err := authedPost(adminHTTP, admin.jwt, serverURL+"/api/sync/pull", pullBody)
	if err != nil {
		check("Sync: admin pull of member record", err)
	} else {
		var pull struct {
			Records []struct{} `json:"records"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&pull)
		resp.Body.Close()
		if decodeErr != nil {
			check("Sync: admin pull of member record returns nothing", fmt.Errorf("decode: %w", decodeErr))
		} else if len(pull.Records) != 0 {
			check("Sync: admin pull of member record returns nothing", fmt.Errorf("got %d records", len(pull.Records)))
		} else {
			check("Sync: admin pull of member record returns nothing", nil)
		}
	}

	err = pushRecord(adminHTTP, admin.jwt, "m3-private", "task")
	if err == nil {
		check("Sync: cross-user overwrite rejected", fmt.Errorf("admin overwrote member3's record"))
	} else {
		check("Sync: cross-user overwrite rejected", nil)
	}

	selfCode, err := createInviteFull(m3HTTP, m3JWT, serverURL, map[string]interface{}{
		"expires_in_seconds": 3600,
		"target_user_id":     m3UserID,
	})
	check("Sync: member3 mints self-service invite", err)
	if err == nil {
		secondKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, _, uid, pairErr := pairWithInviteKey(secondKey, selfCode, "E2E Member3", "m3-second-device")
		check("Sync: self-invite pairs second device", pairErr)
		if pairErr == nil && uid != m3UserID {
			check("Sync: second device joins same user", fmt.Errorf("got %q want %q", uid, m3UserID))
		} else if pairErr == nil {
			check("Sync: second device joins same user", nil)
		}
	}

	_, err = createInviteFull(m3HTTP, m3JWT, serverURL, map[string]interface{}{
		"expires_in_seconds": 3600,
		"target_user_id":     admin.userID,
	})
	if err == nil {
		check("Sync: member cross-user invite forbidden", fmt.Errorf("expected 403"))
	} else {
		check("Sync: member cross-user invite forbidden", nil)
	}

	listResp, err := authedGet(m3HTTP, m3JWT, serverURL+"/api/invites")
	if err != nil {
		check("Sync: member invite list", err)
	} else {
		var invites []struct {
			TargetUserID string `json:"target_user_id"`
		}
		decodeErr := json.NewDecoder(listResp.Body).Decode(&invites)
		listResp.Body.Close()
		ownOnly := true
		for _, inv := range invites {
			if inv.TargetUserID != m3UserID {
				ownOnly = false
			}
		}
		if decodeErr != nil {
			check("Sync: member sees only own invites", fmt.Errorf("decode: %w", decodeErr))
		} else if !ownOnly {
			check("Sync: member sees only own invites", fmt.Errorf("foreign invites visible: %+v", invites))
		} else {
			check("Sync: member sees only own invites", nil)
		}
	}

	req := newRequest("DELETE", serverURL+"/api/users/"+m3UserID+"?purge_data=true", nil)
	req.Header.Set("Authorization", "Bearer "+admin.jwt)
	delResp, err := adminHTTP.Do(req)
	if err != nil {
		check("Sync: revoke member3 with purge", err)
		return passed, failed
	}
	delBody, _ := io.ReadAll(delResp.Body)
	delResp.Body.Close()
	if delResp.StatusCode != 200 {
		check("Sync: revoke member3 with purge", fmt.Errorf("status %d: %s", delResp.StatusCode, delBody))
		return passed, failed
	}
	var delResult struct {
		PurgedRecords int64 `json:"purged_records"`
	}
	_ = json.Unmarshal(delBody, &delResult)
	if delResult.PurgedRecords < 1 {
		check("Sync: purge reports owned records", fmt.Errorf("purged_records %d, want >= 1", delResult.PurgedRecords))
	} else {
		check("Sync: purge reports owned records", nil)
	}
	check("Sync: revoke member3 with purge", nil)

	return passed, failed
}
