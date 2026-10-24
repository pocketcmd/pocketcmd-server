package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const CurrentConfigVersion = 1

var ErrConfigTooNew = errors.New("config.json was written by a newer pcmd; upgrade the binary or restore an older backup")

const DefaultPushRelayURL = "https://push.pocketcmd.com"

type FeatureConfig struct {
	ConfigVersion int    `json:"config_version"`
	ServiceMode   string `json:"service_mode"`   // "background" or "foreground"
	Port          int    `json:"port,omitempty"` // 0 means the flag default
	Host          string `json:"host,omitempty"` // "" means the flag default
	AdvertiseIP   string `json:"advertise_ip,omitempty"`
}

func DefaultFeatureConfig() FeatureConfig {
	return FeatureConfig{
		ConfigVersion: CurrentConfigVersion,
		ServiceMode:   "background",
	}
}

func LoadFeatureConfig(path string) (FeatureConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FeatureConfig{}, err
	}
	var cfg FeatureConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return FeatureConfig{}, err
	}
	if cfg.ConfigVersion > CurrentConfigVersion {
		return FeatureConfig{}, fmt.Errorf("%w (config_version %d, this binary knows %d)",
			ErrConfigTooNew, cfg.ConfigVersion, CurrentConfigVersion)
	}
	return cfg, nil
}

func SaveFeatureConfig(path string, cfg FeatureConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpPath) }
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
