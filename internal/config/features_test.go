package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultFeatureConfig(t *testing.T) {
	cfg := DefaultFeatureConfig()
	if cfg.ServiceMode != "background" {
		t.Errorf("ServiceMode should be 'background', got %q", cfg.ServiceMode)
	}
	if cfg.ConfigVersion != CurrentConfigVersion {
		t.Errorf("ConfigVersion should be %d, got %d", CurrentConfigVersion, cfg.ConfigVersion)
	}
}

func TestSaveAndLoadFeatureConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultFeatureConfig()
	cfg.ServiceMode = "foreground"

	if err := SaveFeatureConfig(path, cfg); err != nil {
		t.Fatalf("SaveFeatureConfig: %v", err)
	}

	loaded, err := LoadFeatureConfig(path)
	if err != nil {
		t.Fatalf("LoadFeatureConfig: %v", err)
	}

	if loaded.ServiceMode != "foreground" {
		t.Errorf("ServiceMode should be 'foreground', got %q", loaded.ServiceMode)
	}
	if loaded.ConfigVersion != CurrentConfigVersion {
		t.Errorf("ConfigVersion should be %d, got %d", CurrentConfigVersion, loaded.ConfigVersion)
	}
}

func TestLoadFeatureConfig_NewerVersionRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"config_version": 99, "service_mode": "background"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFeatureConfig(path)
	if !errors.Is(err, ErrConfigTooNew) {
		t.Fatalf("expected ErrConfigTooNew, got %v", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatal("a too-new config must not look like a missing one")
	}
	if _, err := LoadFeatureConfig(filepath.Join(t.TempDir(), "nope.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing config: want os.ErrNotExist, got %v", err)
	}
}
