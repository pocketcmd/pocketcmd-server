package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
)

func TestValidateRelayURL(t *testing.T) {
	ok := map[string]string{
		"  https://push.example.com/  ": "https://push.example.com",
		"https://push.example.com:8443": "https://push.example.com:8443",
		"http://localhost:9000/":        "http://localhost:9000",
		"http://127.0.0.1:9000":         "http://127.0.0.1:9000",
		"http://[::1]:9000":             "http://[::1]:9000",
		"https://relay.internal/path/":  "https://relay.internal/path",
	}
	for in, want := range ok {
		got, err := validateRelayURL(in)
		if err != nil || got != want {
			t.Errorf("validateRelayURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"",
		"http://push.example.com",
		"http://10.0.0.5:9000",
		"ftp://push.example.com",
		"push.example.com",
		"https://",
		"https://user:pw@push.example.com",
		"https://push.example.com/?x=1",
		"https://push.example.com/#frag",
	}
	for _, in := range bad {
		if got, err := validateRelayURL(in); err == nil {
			t.Errorf("validateRelayURL(%q) accepted as %q", in, got)
		}
	}
}

func TestPushRelayURL_EnvOverride(t *testing.T) {
	for _, c := range []struct {
		env, want, wantLog string
	}{
		{"", config.DefaultPushRelayURL, ""},
		{"   ", config.DefaultPushRelayURL, ""},
		{"http://127.0.0.1:9/", "http://127.0.0.1:9", "level=WARN msg=\"[push] non-default push relay in use"},
		{"http://10.0.0.5:9", config.DefaultPushRelayURL, "level=WARN msg=\"[push] ignoring invalid " + pushRelayEnv},
	} {
		t.Setenv(pushRelayEnv, c.env)
		var logs bytes.Buffer
		got := pushRelayURL(slog.New(slog.NewTextHandler(&logs, nil)))
		if got != c.want {
			t.Errorf("env %q: relay %q, want %q", c.env, got, c.want)
		}
		if c.wantLog == "" && logs.Len() != 0 {
			t.Errorf("env %q: unexpected log %q", c.env, logs.String())
		}
		if c.wantLog != "" && !strings.Contains(logs.String(), c.wantLog) {
			t.Errorf("env %q: expected %q in %q", c.env, c.wantLog, logs.String())
		}
	}
}
