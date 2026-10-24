package metrics

import (
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func TestRequestStore_PruneDecided(t *testing.T) {
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewRequestStore(db)

	now := time.Now().UTC()
	old := now.Add(-31 * 24 * time.Hour).Format(time.RFC3339)
	recent := now.Add(-time.Hour).Format(time.RFC3339)
	seed := func(id, status, decidedAt string) {
		if _, err := db.Exec(`INSERT INTO metric_requests (id, label, command, created_at, status, decided_at)
			VALUES (?, 'l', 'uptime', ?, ?, ?)`, id, old, status, decidedAt); err != nil {
			t.Fatal(err)
		}
	}
	seed("old-declined", "declined", old)
	seed("old-approved-orphan", "approved", old)
	seed("old-approved-live", "approved", old)
	seed("new-declined", "declined", recent)
	seed("pending", "pending", "")
	if _, err := db.Exec(`INSERT INTO custom_metrics (id, label, command, request_id) VALUES ('c1', 'l', 'uptime', 'old-approved-live')`); err != nil {
		t.Fatal(err)
	}

	n, err := s.PruneDecided(now.Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("pruned %d, want 2", n)
	}
	for _, id := range []string{"old-approved-live", "new-declined", "pending"} {
		if req, _ := s.FindByID(id); req == nil {
			t.Fatalf("%s must survive", id)
		}
	}
	for _, id := range []string{"old-declined", "old-approved-orphan"} {
		if req, _ := s.FindByID(id); req != nil {
			t.Fatalf("%s must be pruned", id)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM custom_metrics").Scan(&count); err != nil || count != 1 {
		t.Fatalf("custom_metrics count=%d err=%v, want 1", count, err)
	}
}
