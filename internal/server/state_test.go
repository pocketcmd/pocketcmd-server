package server

import (
	"database/sql"
	"sync"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func testStateDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

var (
	registryDBsMu sync.Mutex
	registryDBs   = map[*pki.DeviceRegistry]*sql.DB{}
)

func testDeviceRegistryOn(db *sql.DB) *pki.DeviceRegistry {
	r := pki.NewDeviceRegistry(db)
	registryDBsMu.Lock()
	registryDBs[r] = db
	registryDBsMu.Unlock()
	return r
}

func testDeviceRegistry(t *testing.T) *pki.DeviceRegistry {
	t.Helper()
	return testDeviceRegistryOn(testStateDB(t))
}

func registryDB(t *testing.T, r *pki.DeviceRegistry) *sql.DB {
	t.Helper()
	registryDBsMu.Lock()
	db, ok := registryDBs[r]
	registryDBsMu.Unlock()
	if !ok {
		t.Fatal("device registry was not built by testDeviceRegistry/testDeviceRegistryOn")
	}
	return db
}

func bindDeviceToUserID(t *testing.T, registry *pki.DeviceRegistry, deviceID, userID string) {
	t.Helper()
	res, err := registryDB(t, registry).Exec("UPDATE devices SET user_id=? WHERE device_id=?", userID, deviceID)
	if err != nil {
		t.Fatalf("reassign device %s: %v", deviceID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		t.Fatalf("reassign device %s: no such device", deviceID)
	}
}

func removeDevice(t *testing.T, registry *pki.DeviceRegistry, deviceID string) {
	t.Helper()
	if _, err := registryDB(t, registry).Exec("DELETE FROM devices WHERE device_id=?", deviceID); err != nil {
		t.Fatalf("remove device %s: %v", deviceID, err)
	}
}
