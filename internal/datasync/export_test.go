package datasync

import (
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func NewSyncStoreAt(dir string) *SyncStore {
	db, err := state.Open(dir)
	if err != nil {
		panic("sync store: " + err.Error())
	}
	return NewSyncStore(db, monitoring.NewStore(db))
}

func (s *SyncStore) Close() error {
	return nil
}
