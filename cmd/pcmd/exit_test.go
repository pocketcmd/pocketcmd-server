package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		err  error
		code int
		msg  string
	}{
		{nil, exitOK, ""},
		{errors.New("boom"), exitError, "boom"},
		{exitWith(exitNotInstalled, "not installed"), exitNotInstalled, "not installed"},
		{exitSilently(exitServiceStopped), exitServiceStopped, ""},
		{errInterrupted, exitInterrupted, ""},
	}
	for _, c := range cases {
		code, msg := exitCodeFor(c.err)
		if code != c.code || msg != c.msg {
			t.Errorf("exitCodeFor(%v) = (%d, %q), want (%d, %q)", c.err, code, msg, c.code, c.msg)
		}
	}
}

func TestReportExit_PrintsOnlyNonSilentErrors(t *testing.T) {
	var buf bytes.Buffer
	if code := reportExit(&buf, errors.New("port busy")); code != exitError || !strings.Contains(buf.String(), "Error: port busy") {
		t.Fatalf("code=%d out=%q", code, buf.String())
	}
	buf.Reset()
	if code := reportExit(&buf, errInterrupted); code != exitInterrupted || buf.Len() != 0 {
		t.Fatalf("silent error must print nothing: code=%d out=%q", code, buf.String())
	}
}

func TestCheckHome(t *testing.T) {
	if err := checkHome(func() (string, error) { return "/home/x", nil }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := checkHome(func() (string, error) { return "", errors.New("$HOME is not defined") })
	if err == nil || !strings.Contains(err.Error(), "HOME") {
		t.Fatalf("expected a HOME error, got %v", err)
	}
	if err := checkHome(func() (string, error) { return "", nil }); err == nil {
		t.Fatal("empty home must be an error")
	}
}

func discard() *bytes.Buffer { return &bytes.Buffer{} }
