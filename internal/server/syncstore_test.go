package server

import (
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func newTestSyncStore(t *testing.T) *datasync.SyncStore {
	t.Helper()
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return datasync.NewSyncStore(db, monitoring.NewStore(db))
}
