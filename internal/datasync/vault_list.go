package datasync

type VaultSummary struct {
	VaultID string `json:"vault_id"`
	Members int    `json:"members"`
}

func (s *SyncStore) ListVaults() ([]VaultSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(
		"SELECT vault_id, COUNT(*) FROM vault_acl GROUP BY vault_id ORDER BY vault_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultSummary
	for rows.Next() {
		var v VaultSummary
		if err := rows.Scan(&v.VaultID, &v.Members); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
