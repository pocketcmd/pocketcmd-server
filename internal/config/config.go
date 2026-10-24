// Package config holds the state directory paths and on-disk configuration.
package config

import (
	"os"
	"path/filepath"
)

var pocketCmdDirOverride string

func SetPocketCmdDir(dir string) { pocketCmdDirOverride = dir }

func PocketCmdDir() string {
	if pocketCmdDirOverride != "" {
		return pocketCmdDirOverride
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".pocketcmd")
}

func TLSDir() string { return filepath.Join(PocketCmdDir(), "tls") }

func ConfigFilePath() string {
	return filepath.Join(PocketCmdDir(), "config.json")
}

type ServerConfig struct {
	Port           int
	Host           string
	PollIntervalMs int
}
