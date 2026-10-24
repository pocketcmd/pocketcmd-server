package pki

import (
	"database/sql"
	"testing"

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
