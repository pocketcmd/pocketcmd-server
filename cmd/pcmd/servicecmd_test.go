package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/service"
)

type fakeService struct {
	installed, running bool
	matches            bool
	healthy            bool
	calls              []string
	startErr, stopErr  error
	writeErr           error
}

func (f *fakeService) bind(t *testing.T) {
	t.Helper()
	orig := svc
	t.Cleanup(func() { svc = orig })
	svc = serviceAPI{
		isInstalled: func() bool { return f.installed },
		status: func() service.ServiceStatus {
			return service.ServiceStatus{Installed: f.installed, Running: f.running, PID: 4242}
		},
		install: func(string, int, string) ([]string, error) {
			f.calls = append(f.calls, "install")
			f.installed, f.running = true, true
			return nil, nil
		},
		writeFile: func(string, int, string) ([]string, error) {
			f.calls = append(f.calls, "write")
			if f.writeErr != nil {
				return nil, f.writeErr
			}
			f.installed = true
			return nil, nil
		},
		fileMatches: func(string, int, string) (bool, error) { return f.matches, nil },
		start: func() error {
			f.calls = append(f.calls, "start")
			if f.startErr != nil {
				return f.startErr
			}
			f.running = true
			return nil
		},
		stop: func() error {
			f.calls = append(f.calls, "stop")
			if f.stopErr != nil {
				return f.stopErr
			}
			f.running = false
			return nil
		},
		uninstall: func() error {
			f.calls = append(f.calls, "uninstall")
			f.installed, f.running = false, false
			return nil
		},
		waitHealthy: func(string, int, time.Duration) error {
			if f.healthy {
				return nil
			}
			return errors.New("unhealthy")
		},
		healthCheck: func(string, int) error {
			if f.healthy && f.running {
				return nil
			}
			return errors.New("down")
		},
		lingerStatus: func() (bool, bool) { return false, false },
	}
}

func TestStopStart_NotInstalled(t *testing.T) {
	f := &fakeService{}
	f.bind(t)
	for _, fn := range []func(*bytes.Buffer) error{
		func(b *bytes.Buffer) error { return stopService(b) },
		func(b *bytes.Buffer) error { return startService(b, 8767, "127.0.0.1") },
	} {
		if err := fn(&bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	for _, name := range []string{"stop", "start", "restart"} {
		if _, _, err := runCLI(t, name); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Fatalf("%s on a bare host must refuse: %v", name, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("nothing may be called on a bare host: %v", f.calls)
	}
}

func TestStop_StopsWithoutUninstalling(t *testing.T) {
	f := &fakeService{installed: true, running: true}
	f.bind(t)
	var out bytes.Buffer
	if err := stopService(&out); err != nil {
		t.Fatal(err)
	}
	if !f.installed || f.running || strings.Join(f.calls, ",") != "stop" {
		t.Fatalf("stop must only stop: installed=%v running=%v calls=%v", f.installed, f.running, f.calls)
	}
	if !strings.Contains(out.String(), "Service stopped.") {
		t.Fatalf("output: %q", out.String())
	}
	out.Reset()
	if err := stopService(&out); err != nil || !strings.Contains(out.String(), "not running") {
		t.Fatalf("second stop: err=%v out=%q", err, out.String())
	}
	f.running, f.stopErr = true, errors.New("systemctl exploded")
	if err := stopService(&out); err == nil || !strings.Contains(err.Error(), "systemctl exploded") {
		t.Fatalf("stop error must surface: %v", err)
	}
}

func TestStart_StartsAndReportsHealth(t *testing.T) {
	f := &fakeService{installed: true, healthy: true}
	f.bind(t)
	var out bytes.Buffer
	if err := startService(&out, 8767, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !f.running || !strings.Contains(out.String(), "Service started.") {
		t.Fatalf("running=%v out=%q", f.running, out.String())
	}
	out.Reset()
	if err := startService(&out, 8767, "127.0.0.1"); err != nil || !strings.Contains(out.String(), "already running") {
		t.Fatalf("start twice: err=%v out=%q", err, out.String())
	}
	f.running, f.healthy = false, false
	out.Reset()
	if code, msg := exitCodeFor(startService(&out, 8767, "127.0.0.1")); code != exitUnhealthy || !strings.Contains(msg, "health check failed") {
		t.Fatalf("an unhealthy start must exit %d: code=%d msg=%q", exitUnhealthy, code, msg)
	}
	f.running, f.startErr = false, errors.New("launchctl refused")
	if err := startService(&out, 8767, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "launchctl refused") {
		t.Fatalf("start error must surface: %v", err)
	}
}

func TestRestart_KeepsMatchingUnit(t *testing.T) {
	f := &fakeService{installed: true, running: true, matches: true, healthy: true}
	f.bind(t)
	var out bytes.Buffer
	if err := restartService(&out, 8767, "0.0.0.0"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls, ","); got != "stop,start" {
		t.Fatalf("a matching unit must be stopped and started, not reinstalled: %s", got)
	}
	if !strings.Contains(out.String(), "restarted successfully") {
		t.Fatalf("output: %q", out.String())
	}
}

func TestRestart_ReinstallsChangedUnit(t *testing.T) {
	f := &fakeService{installed: true, running: true, matches: false, healthy: false}
	f.bind(t)
	var out bytes.Buffer
	err := restartService(&out, 9000, "127.0.0.1")
	if got := strings.Join(f.calls, ","); got != "uninstall,install" {
		t.Fatalf("a changed unit must be reinstalled: %s", got)
	}
	if !strings.Contains(out.String(), "out of date") {
		t.Fatalf("output: %q", out.String())
	}
	if code, msg := exitCodeFor(err); code != exitUnhealthy || !strings.Contains(msg, "health check failed") {
		t.Fatalf("an unhealthy restart must exit %d: code=%d msg=%q", exitUnhealthy, code, msg)
	}
}

func TestUninstall_RemovesWhenConfirmedWithYes(t *testing.T) {
	f := &fakeService{installed: true, running: true}
	f.bind(t)
	var out bytes.Buffer
	if err := uninstallCore(&out, true, true); err != nil {
		t.Fatal(err)
	}
	if f.installed || strings.Join(f.calls, ",") != "uninstall" {
		t.Fatalf("installed=%v calls=%v", f.installed, f.calls)
	}
	f.installed = true
	if err := uninstallCore(&out, false, true); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("non-interactive uninstall without --yes must refuse: %v", err)
	}
}
