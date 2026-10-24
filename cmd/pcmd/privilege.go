package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/pocketcmd/pocketcmd-server/internal/service"
)

type privilegeContext struct {
	euid       int
	sudoUser   string
	goos       string
	initSystem string
}

func currentPrivileges() privilegeContext {
	pc := privilegeContext{
		euid:     os.Geteuid(),
		sudoUser: os.Getenv("SUDO_USER"),
		goos:     runtime.GOOS,
	}
	if pc.goos == "linux" {
		pc.initSystem = service.DetectInitSystem()
	}
	return pc
}

// OpenRC is a system service that legitimately needs root; with no init system there is nothing to install.
func (pc privilegeContext) perUserService() bool {
	switch pc.goos {
	case "darwin":
		return true
	case "linux":
		return pc.initSystem == "systemd"
	}
	return false
}

func checkPrivileges(pc privilegeContext) error {
	if !pc.perUserService() {
		return nil
	}
	if pc.sudoUser != "" {
		return fmt.Errorf("refusing to run under sudo: pcmd installs a per-user service and keeps its state in the user's home, "+
			"so it must run as the account that will own the server; run it again as %s without sudo", pc.sudoUser)
	}
	if pc.euid == 0 {
		msg := "refusing to run as root: pcmd installs a per-user service (a %s) and keeps its state in the user's home. " +
			"Log in as a normal user and run it there"
		if pc.goos == "linux" {
			return fmt.Errorf(msg+"; then run `loginctl enable-linger <user>` so the service keeps running after logout", "systemd user unit")
		}
		return fmt.Errorf(msg, "launchd agent")
	}
	return nil
}
