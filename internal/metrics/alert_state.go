package metrics

import (
	"database/sql"
	"time"
)

type AlertRuleState struct {
	LastFired    time.Time
	EpisodeFired bool // the current breach episode already pushed
	Breached     bool
}

type AlertStateStore struct {
	db *sql.DB
}

func NewAlertStateStore(db *sql.DB) *AlertStateStore {
	return &AlertStateStore{db: db}
}

func (s *AlertStateStore) Load() (map[string]AlertRuleState, error) {
	rows, err := s.db.Query("SELECT rule_id, last_fired, episode_fired, breached FROM alert_state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AlertRuleState{}
	for rows.Next() {
		var id string
		var lastFired int64
		var episode, breached int
		if err := rows.Scan(&id, &lastFired, &episode, &breached); err != nil {
			return nil, err
		}
		st := AlertRuleState{EpisodeFired: episode != 0, Breached: breached != 0}
		if lastFired > 0 {
			st.LastFired = time.UnixMilli(lastFired)
		}
		out[id] = st
	}
	return out, rows.Err()
}

func (s *AlertStateStore) Save(ruleID string, st AlertRuleState) error {
	var lastFired int64
	if !st.LastFired.IsZero() {
		lastFired = st.LastFired.UnixMilli()
	}
	_, err := s.db.Exec(`INSERT INTO alert_state (rule_id, last_fired, episode_fired, breached, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(rule_id) DO UPDATE SET
			last_fired=excluded.last_fired,
			episode_fired=excluded.episode_fired,
			breached=excluded.breached,
			updated_at=excluded.updated_at`,
		ruleID, lastFired, boolInt(st.EpisodeFired), boolInt(st.Breached), time.Now().UnixMilli())
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
