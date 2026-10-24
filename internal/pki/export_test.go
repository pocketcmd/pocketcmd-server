package pki

import "io/fs"

func (r *DeviceRegistry) Remove(deviceID string) error {
	res, err := r.db.Exec("DELETE FROM devices WHERE device_id=?", deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fs.ErrNotExist
	}
	return nil
}
