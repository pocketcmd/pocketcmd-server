package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var errNotInstalled = fmt.Errorf("PocketCmd is not installed as a service; run 'pcmd install' first")

func runStop(cmd *cobra.Command, args []string) error {
	return stopService(cmd.OutOrStdout())
}

func stopService(w io.Writer) error {
	if !svc.isInstalled() {
		return errNotInstalled
	}
	if !svc.status().Running {
		fmt.Fprintln(w, "Service is not running.")
		return nil
	}
	if err := svc.stop(); err != nil {
		return fmt.Errorf("stop failed: %w", err)
	}
	fmt.Fprintln(w, "Service stopped.")
	return nil
}

func runStart(cmd *cobra.Command, args []string) error {
	port, host, _ := runtimeSettings(cmd)
	return startService(cmd.OutOrStdout(), port, host)
}

func startService(w io.Writer, port int, host string) error {
	if !svc.isInstalled() {
		return errNotInstalled
	}
	if svc.status().Running {
		fmt.Fprintln(w, "Service is already running.")
		return nil
	}
	if err := svc.start(); err != nil {
		return fmt.Errorf("start failed: %w", err)
	}
	if err := svc.waitHealthy(host, port, 10*time.Second); err != nil {
		fmt.Fprintln(w, "Warning: service started but the health check failed. See 'pcmd status'.")
		return nil
	}
	fmt.Fprintln(w, "Service started.")
	return nil
}

func runRestart(cmd *cobra.Command, args []string) error {
	if !svc.isInstalled() {
		return errNotInstalled
	}
	port, host, _ := runtimeSettings(cmd)
	return restartService(cmd.OutOrStdout(), port, host)
}

func restartService(w io.Writer, port int, host string) error {
	binPath, _ := os.Executable()
	matches, _ := svc.fileMatches(binPath, port, host)
	if matches {
		fmt.Fprintln(w, "Stopping service...")
		if err := svc.stop(); err != nil {
			return fmt.Errorf("stop failed: %w", err)
		}
		fmt.Fprintln(w, "Starting service...")
		if err := svc.start(); err != nil {
			return fmt.Errorf("start failed: %w", err)
		}
	} else {
		fmt.Fprintln(w, "Service definition is out of date; reinstalling...")
		if err := svc.uninstall(); err != nil {
			return fmt.Errorf("stop failed: %w", err)
		}
		warnings, err := svc.install(binPath, port, host)
		printServiceWarnings(w, warnings)
		if err != nil {
			return fmt.Errorf("start failed: %w", err)
		}
	}

	// install.sh rolls an update back on exitUnhealthy and only on it.
	if err := svc.waitHealthy(host, port, 10*time.Second); err != nil {
		return exitWith(exitUnhealthy, fmt.Sprintf("service restarted but the health check failed (see 'pcmd logs'): %v", err))
	}
	fmt.Fprintln(w, "Service restarted successfully.")
	return nil
}
