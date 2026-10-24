package main

import (
	"database/sql"
	"fmt"
	"sync"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

// Keyed by directory rather than a sync.Once because tests and the one-shot sync repoint PocketCmdDir within one process.
var (
	stateDBMu sync.Mutex
	stateDBs  = map[string]*sql.DB{}
)

func stateDB() (*sql.DB, error) {
	dir := config.PocketCmdDir()
	stateDBMu.Lock()
	defer stateDBMu.Unlock()
	if db, ok := stateDBs[dir]; ok {
		return db, nil
	}
	db, err := state.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("state database: %w", err)
	}
	stateDBs[dir] = db
	return db, nil
}
