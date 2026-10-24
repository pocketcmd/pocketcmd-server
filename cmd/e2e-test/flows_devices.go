package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

func deviceFlow(srvComp testServerComponents, admin adminCredentials) (int, int) {
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

	firstHTTP, _, err := buildMTLSClient(admin.key, admin.certPEM)
	if err != nil {
		check("Device: admin mTLS client", err)
		return passed, failed
	}

	// Drive the flow from a second owner device; the first one is near its rate budget.
	ownerCode, err := createInviteFull(firstHTTP, admin.jwt, serverURL, map[string]interface{}{
		"target_user_id": admin.userID,
	})
	if err != nil {
		check("Device: second-device invite for the owner", err)
		return passed, failed
	}
	ownerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ownerCertPEM, ownerUserID, err := pairWithInviteKey(ownerKey, ownerCode, admin.displayName, "owner-second-device")
	if err != nil || ownerUserID != admin.userID {
		check("Device: owner pairs a second device", fmt.Errorf("err=%v user=%q", err, ownerUserID))
		return passed, failed
	}
	adminHTTP, _, _ := buildMTLSClient(ownerKey, ownerCertPEM)
	adminJWT, err := getSession(adminHTTP, srvComp.registry)
	if err != nil {
		check("Device: owner second-device JWT session", err)
		return passed, failed
	}
	admin.jwt = adminJWT

	code, err := createInviteHTTP(adminHTTP, admin.jwt, serverURL)
	if err != nil {
		check("Device: create member invite", err)
		return passed, failed
	}
	memKey, memCertPEM, memUserID, err := redeemInvite(srvComp.pairHandler, code, "E2E Device Member")
	if err != nil {
		check("Device: member redeems invite", err)
		return passed, failed
	}
	memHTTP, _, _ := buildMTLSClient(memKey, memCertPEM)
	memJWT, err := getSession(memHTTP, srvComp.registry)
	if err != nil {
		check("Device: member JWT session", err)
		return passed, failed
	}
	memDevices, _ := srvComp.registry.DevicesByUserID(memUserID)
	if len(memDevices) != 1 {
		check("Device: member device registered", fmt.Errorf("got %d devices", len(memDevices)))
		return passed, failed
	}
	memDeviceID := memDevices[0].DeviceID
	adminDevices, _ := srvComp.registry.DevicesByUserID(admin.userID)
	adminDeviceID := adminDevices[0].DeviceID // the owner's FIRST device, not the one calling

	check("Device: PATCH /api/devices/self renames the calling device",
		patchDevice(memHTTP, memJWT, serverURL, "self", `{"device_name":"e2e phone","device_label":"pocket"}`,
			http.StatusOK, "", func(d deviceObject) error {
				if d.DeviceID != memDeviceID || d.DeviceName != "e2e phone" || d.DeviceLabel != "pocket" || !d.Self || d.Status != "active" || d.RemovedAt != nil {
					return fmt.Errorf("unexpected device object %+v", d)
				}
				return nil
			}))
	check("Device: member cannot rename another user's device",
		patchDevice(memHTTP, memJWT, serverURL, adminDeviceID, `{"device_name":"x"}`, http.StatusForbidden, "forbidden", nil))
	check("Device: admin renames the member's device by id",
		patchDevice(adminHTTP, admin.jwt, serverURL, memDeviceID, `{"device_label":"relabelled"}`, http.StatusOK, "",
			func(d deviceObject) error {
				if d.DeviceName != "e2e phone" || d.DeviceLabel != "relabelled" || d.Self {
					return fmt.Errorf("unexpected device object %+v", d)
				}
				return nil
			}))
	check("Device: PATCH with no fields is 400 no_fields",
		patchDevice(memHTTP, memJWT, serverURL, "self", `{}`, http.StatusBadRequest, "no_fields", nil))
	long := bytes.Repeat([]byte("x"), pki.MaxDeviceNameLen+1)
	check("Device: over-long device name is 400 name_too_long",
		patchDevice(memHTTP, memJWT, serverURL, "self", `{"device_name":"`+string(long)+`"}`, http.StatusBadRequest, "name_too_long", nil))
	check("Device: unknown device is 404 device_not_found",
		patchDevice(adminHTTP, admin.jwt, serverURL, "0000000000000000", `{"device_name":"x"}`, http.StatusNotFound, "device_not_found", nil))

	check("Ownership: non-owner cannot transfer ownership",
		expectTransfer(memHTTP, memJWT, serverURL, admin.userID, http.StatusForbidden, "owner_required"))
	check("Ownership: self transfer is 400 self_transfer",
		expectTransfer(adminHTTP, admin.jwt, serverURL, admin.userID, http.StatusBadRequest, "self_transfer"))
	check("Ownership: transfer to unknown user is 404 user_not_found",
		expectTransfer(adminHTTP, admin.jwt, serverURL, "nobody000000", http.StatusNotFound, "user_not_found"))
	check("Ownership: owner transfers ownership to the member",
		expectTransfer(adminHTTP, admin.jwt, serverURL, memUserID, http.StatusOK, ""))
	if u, _ := srvComp.users.FindByID(memUserID); u == nil || !u.Owner || u.Role != "admin" {
		check("Ownership: new owner is owner+admin", fmt.Errorf("got %+v", u))
	} else {
		check("Ownership: new owner is owner+admin", nil)
	}
	if u, _ := srvComp.users.FindByID(admin.userID); u == nil || u.Owner || u.Role != "admin" {
		check("Ownership: previous owner is a plain admin", fmt.Errorf("got %+v", u))
	} else {
		check("Ownership: previous owner is a plain admin", nil)
	}
	check("Ownership: previous owner is refused on owner-only routes",
		expectStatus(adminHTTP, admin.jwt, "GET", serverURL+"/api/audit", nil, http.StatusForbidden))
	check("Ownership: new owner may read the audit feed",
		expectStatus(memHTTP, memJWT, "GET", serverURL+"/api/audit", nil, http.StatusOK))
	check("Ownership: new owner transfers ownership back",
		expectTransfer(memHTTP, memJWT, serverURL, admin.userID, http.StatusOK, ""))
	if u, _ := srvComp.users.FindByID(admin.userID); u == nil || !u.Owner {
		check("Ownership: ownership restored to the admin", fmt.Errorf("got %+v", u))
	} else {
		check("Ownership: ownership restored to the admin", nil)
	}

	check("Device: member unpairs its device",
		expectStatus(memHTTP, memJWT, "DELETE", serverURL+"/api/devices/self", nil, http.StatusOK))
	check("Device: default device listing hides the left device",
		listDevices(adminHTTP, admin.jwt, serverURL, "", func(list []deviceObject) error {
			for _, d := range list {
				if d.DeviceID == memDeviceID {
					return fmt.Errorf("left device listed by default: %+v", d)
				}
				if d.Status != "active" || d.RemovedAt != nil {
					return fmt.Errorf("default listing must be active-only: %+v", d)
				}
			}
			return nil
		}))
	check("Device: include=all lists the left device with status and removed_at",
		listDevices(adminHTTP, admin.jwt, serverURL, "?include=all", func(list []deviceObject) error {
			for _, d := range list {
				if d.DeviceID == memDeviceID {
					if d.Status != "left" || d.RemovedAt == nil || *d.RemovedAt == "" {
						return fmt.Errorf("left device: %+v", d)
					}
					return nil
				}
			}
			return fmt.Errorf("left device missing from include=all listing")
		}))

	return passed, failed
}

type deviceObject struct {
	DeviceID    string  `json:"device_id"`
	DeviceName  string  `json:"device_name"`
	DeviceLabel string  `json:"device_label"`
	UserID      string  `json:"user_id"`
	Status      string  `json:"status"`
	RemovedAt   *string `json:"removed_at"`
	Self        bool    `json:"self"`
}

func doJSON(client *http.Client, jwt, method, url string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := newRequest(method, url, reader)
	req.Header.Set("Authorization", "Bearer "+jwt)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

func expectErrorCode(body []byte, want string) error {
	if want == "" {
		return nil
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("decode error body: %w (%s)", err, body)
	}
	if e.Error != want {
		return fmt.Errorf("error code %q, want %q", e.Error, want)
	}
	return nil
}

func expectStatus(client *http.Client, jwt, method, url string, body []byte, want int) error {
	status, respBody, err := doJSON(client, jwt, method, url, body)
	if err != nil {
		return err
	}
	if status != want {
		return fmt.Errorf("status %d (want %d): %s", status, want, respBody)
	}
	return nil
}

func patchDevice(client *http.Client, jwt, serverURL, id, body string, wantStatus int, wantErr string, verify func(deviceObject) error) error {
	status, respBody, err := doJSON(client, jwt, "PATCH", serverURL+"/api/devices/"+id, []byte(body))
	if err != nil {
		return err
	}
	if status != wantStatus {
		return fmt.Errorf("status %d (want %d): %s", status, wantStatus, respBody)
	}
	if err := expectErrorCode(respBody, wantErr); err != nil {
		return err
	}
	if verify != nil {
		var d deviceObject
		if err := json.Unmarshal(respBody, &d); err != nil {
			return fmt.Errorf("decode device: %w (%s)", err, respBody)
		}
		return verify(d)
	}
	return nil
}

func listDevices(client *http.Client, jwt, serverURL, query string, verify func([]deviceObject) error) error {
	status, respBody, err := doJSON(client, jwt, "GET", serverURL+"/api/devices"+query, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, respBody)
	}
	var list []deviceObject
	if err := json.Unmarshal(respBody, &list); err != nil {
		return fmt.Errorf("decode list: %w", err)
	}
	return verify(list)
}

func expectTransfer(client *http.Client, jwt, serverURL, targetID string, wantStatus int, wantErr string) error {
	status, respBody, err := doJSON(client, jwt, "POST", serverURL+"/api/users/"+targetID+"/transfer-ownership", nil)
	if err != nil {
		return err
	}
	if status != wantStatus {
		return fmt.Errorf("status %d (want %d): %s", status, wantStatus, respBody)
	}
	if wantErr != "" {
		return expectErrorCode(respBody, wantErr)
	}
	var resp map[string]string
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if resp["status"] != "ok" || resp["new_owner"] != targetID || resp["previous_owner"] == "" {
		return fmt.Errorf("unexpected body %v", resp)
	}
	return nil
}
