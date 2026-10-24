package config

import (
	"strings"
	"testing"
)

func TestPocketCmdDir(t *testing.T) {
	dir := PocketCmdDir()
	if dir == "" {
		t.Fatal("dir should not be empty")
	}
}

func TestTLSDir(t *testing.T) {
	dir := TLSDir()
	if dir == "" {
		t.Fatal("TLSDir should not be empty")
	}
	if !strings.HasSuffix(dir, ".pocketcmd/tls") {
		t.Fatalf("expected .pocketcmd/tls suffix, got %s", dir)
	}
}

func TestConfigFilePath(t *testing.T) {
	path := ConfigFilePath()
	if !strings.HasSuffix(path, ".pocketcmd/config.json") {
		t.Fatalf("expected .pocketcmd/config.json suffix, got %s", path)
	}
}
