package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func TestRuntimeSettings_ConfigThenFlagsPrecedence(t *testing.T) {
	testutil.TempHome(t)
	dir := config.PocketCmdDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultFeatureConfig()
	cfg.Port = 9000
	cfg.Host = "10.8.0.1"
	cfg.AdvertiseIP = "10.8.0.1"
	if err := config.SaveFeatureConfig(config.ConfigFilePath(), cfg); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"invites"})
	if err := root.ParseFlags([]string{}); err != nil {
		t.Fatal(err)
	}
	port, host, adv := runtimeSettings(root)
	if port != 9000 || host != "10.8.0.1" || adv != "10.8.0.1" {
		t.Fatalf("config values not applied: port=%d host=%q adv=%q", port, host, adv)
	}

	root = newRootCmd()
	if err := root.ParseFlags([]string{"--port", "8800", "--advertise-ip", "192.168.1.5"}); err != nil {
		t.Fatal(err)
	}
	port, host, adv = runtimeSettings(root)
	if port != 8800 || host != "10.8.0.1" || adv != "192.168.1.5" {
		t.Fatalf("flags must override config only where passed: port=%d host=%q adv=%q", port, host, adv)
	}
}

func TestRuntimeSettings_NoConfigUsesFlagDefaults(t *testing.T) {
	testutil.TempHome(t)
	root := newRootCmd()
	if err := root.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	port, host, adv := runtimeSettings(root)
	if port != 8767 || host != defaultBindHost() || adv != "" {
		t.Fatalf("unexpected defaults: port=%d host=%q adv=%q", port, host, adv)
	}
}

func TestFeatureConfig_PortHostRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"config_version":1,"service_mode":"background"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFeatureConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 0 || cfg.Host != "" {
		t.Fatalf("legacy config must leave port/host unset: %+v", cfg)
	}
	cfg.Port = 9001
	cfg.Host = "127.0.0.1"
	if err := config.SaveFeatureConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	back, err := config.LoadFeatureConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Port != 9001 || back.Host != "127.0.0.1" {
		t.Fatalf("port/host not persisted: %+v", back)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config.json must stay owner-only: %v %v", info.Mode(), err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".config-*")); len(leftovers) != 0 {
		t.Fatalf("temp file left behind: %v", leftovers)
	}
}
