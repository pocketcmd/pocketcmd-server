package datasync

import (
	"database/sql"
	"encoding/json"
	"strings"
)

// Must run inside the transaction that re-binds the device; device_revocation is never touched.
func ResetDeviceKeyRecords(tx *sql.Tx, deviceID string) (int64, error) {
	if deviceID == "" {
		return 0, nil
	}
	res, err := tx.Exec(`DELETE FROM sync_records
		WHERE type IN ('device_vault_key','enroll_request') AND id=?`, deviceID)
	if err != nil {
		return 0, err
	}
	removed, _ := res.RowsAffected()

	// Scan then filter: vault ids may contain '_', a LIKE wildcard.
	rows, err := tx.Query(`SELECT id, data FROM sync_records WHERE type='vault_wrap'`)
	if err != nil {
		return removed, err
	}
	var doomed []string
	for rows.Next() {
		var id, data string
		if err := rows.Scan(&id, &data); err != nil {
			continue
		}
		recipient := wrapRecipientDevice(json.RawMessage(data))
		if recipient == "" {
			if i := strings.IndexByte(id, ':'); i > 0 {
				recipient = id[i+1:]
			}
		}
		if recipient == deviceID {
			doomed = append(doomed, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return removed, err
	}
	rows.Close()

	for _, id := range doomed {
		res, err := tx.Exec(`DELETE FROM sync_records WHERE type='vault_wrap' AND id=?`, id)
		if err != nil {
			return removed, err
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	return removed, nil
}
