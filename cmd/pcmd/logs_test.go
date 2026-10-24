package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/server"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func logEntry(ts time.Time, level, msg string, kv ...any) json.RawMessage {
	m := map[string]any{"time": ts.UTC().Format(time.RFC3339), "level": level, "msg": msg}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	b, _ := json.Marshal(m)
	return b
}

func newTestLogStore(t *testing.T) *server.LogStore {
	t.Helper()
	testutil.TempHome(t)
	return server.NewLogStore(testStateDB(t), 1000)
}

func TestLogsCore_TailOrderLevelAndSince(t *testing.T) {
	store := newTestLogStore(t)
	now := time.Now()
	store.Append(logEntry(now.Add(-3*time.Hour), "INFO", "old"))
	store.Append(logEntry(now.Add(-time.Minute), "DEBUG", "dbg"))
	store.Append(logEntry(now.Add(-30*time.Second), "WARN", "warned", "user_id", "u1"))
	store.Append(logEntry(now.Add(-10*time.Second), "ERROR", "failed", "err", "boom boom"))

	var out bytes.Buffer
	if err := logsCore(&out, store, logOptions{lines: 50}, nil); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || !strings.Contains(lines[0], "old") || !strings.Contains(lines[3], "failed") {
		t.Fatalf("expected 4 lines oldest first, got %q", out.String())
	}
	if !strings.Contains(lines[3], `err="boom boom"`) || !strings.Contains(lines[2], "user_id=u1") {
		t.Fatalf("attributes missing: %q", out.String())
	}

	out.Reset()
	if err := logsCore(&out, store, logOptions{lines: 2}, nil); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 2 || !strings.Contains(lines[0], "warned") {
		t.Fatalf("-n 2 must show the two newest: %q", out.String())
	}

	out.Reset()
	if err := logsCore(&out, store, logOptions{lines: 50, level: "warn"}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "dbg") || strings.Contains(out.String(), "old") || !strings.Contains(out.String(), "warned") || !strings.Contains(out.String(), "failed") {
		t.Fatalf("--level warn: %q", out.String())
	}

	out.Reset()
	if err := logsCore(&out, store, logOptions{lines: 50, since: time.Hour}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "old") || !strings.Contains(out.String(), "dbg") {
		t.Fatalf("--since 1h: %q", out.String())
	}

	out.Reset()
	if err := logsCore(&out, store, logOptions{lines: 1, asJSON: true}, nil); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil || m["msg"] != "failed" {
		t.Fatalf("--json must print the raw entry: %q (%v)", out.String(), err)
	}
}

func TestTailEntries_WalksPagesForLevel(t *testing.T) {
	store := newTestLogStore(t)
	now := time.Now()
	store.Append(logEntry(now.Add(-time.Hour), "ERROR", "first-error"))
	for i := 0; i < 120; i++ {
		store.Append(logEntry(now.Add(-time.Duration(60-i)*time.Second), "INFO", fmt.Sprintf("info-%d", i)))
	}
	got := tailEntries(store, 5, 0, "error")
	if len(got) != 1 || !strings.Contains(string(got[0].Entry), "first-error") {
		t.Fatalf("expected the single error entry, got %d: %v", len(got), got)
	}
}

func TestLogsCore_FollowPrintsNewEntriesAndStopsOnInterrupt(t *testing.T) {
	store := newTestLogStore(t)
	orig := logPollInterval
	logPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { logPollInterval = orig })

	store.Append(logEntry(time.Now(), "INFO", "before"))
	var out syncBuffer
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- logsCore(&out, store, logOptions{lines: 50, follow: true, level: "info"}, stop) }()

	waitFor(t, func() bool { return strings.Contains(out.String(), "before") })
	store.Append(logEntry(time.Now(), "DEBUG", "hidden"))
	store.Append(logEntry(time.Now(), "WARN", "after"))
	waitFor(t, func() bool { return strings.Contains(out.String(), "after") })
	if strings.Contains(out.String(), "hidden") {
		t.Fatal("the level filter must apply while following")
	}
	stop <- syscall.SIGINT
	if err := <-done; err != errInterrupted {
		t.Fatalf("Ctrl+C must end the follow with exit 130, got %v", err)
	}
	if strings.Count(out.String(), "before") != 1 || strings.Count(out.String(), "after") != 1 {
		t.Fatalf("entries must be printed exactly once: %q", out.String())
	}
}

func TestTailFile_TailsAndFollowsWithRotation(t *testing.T) {
	orig := logPollInterval
	logPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { logPollInterval = orig })

	path := filepath.Join(t.TempDir(), "server.log")
	now := time.Now()
	var content strings.Builder
	content.Write(logEntry(now.Add(-2*time.Hour), "INFO", "ancient"))
	content.WriteByte('\n')
	content.Write(logEntry(now, "INFO", "one"))
	content.WriteByte('\n')
	content.Write(logEntry(now, "ERROR", "two"))
	content.WriteByte('\n')
	content.WriteString("not json\n")
	if err := os.WriteFile(path, []byte(content.String()), 0600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := tailFile(&out, path, logOptions{lines: 2, since: time.Hour}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ancient") || !strings.Contains(out.String(), "one") || !strings.Contains(out.String(), "two") {
		t.Fatalf("tail: %q", out.String())
	}
	if strings.Contains(out.String(), "not json") {
		t.Fatalf("a line without a timestamp fails the since filter: %q", out.String())
	}

	var fout syncBuffer
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- tailFile(&fout, path, logOptions{lines: 2, follow: true}, stop) }()
	waitFor(t, func() bool {
		return strings.Contains(fout.String(), "two") && strings.Contains(fout.String(), "not json")
	})

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write(logEntry(now, "INFO", "three"))
	f.Write([]byte("\n"))
	f.Close()
	waitFor(t, func() bool { return strings.Contains(fout.String(), "three") })

	rotated := append(logEntry(now, "INFO", "four"), '\n')
	if err := os.WriteFile(path, rotated, 0600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return strings.Contains(fout.String(), "four") })
	stop <- syscall.SIGINT
	if err := <-done; err != errInterrupted {
		t.Fatalf("expected interrupt, got %v", err)
	}

	if err := tailFile(&out, filepath.Join(t.TempDir(), "missing"), logOptions{lines: 1}, nil); err == nil {
		t.Fatal("a missing file must be an error")
	}
}

func TestFormatEntryAndLevels(t *testing.T) {
	e := logEntry(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "INFO", "hello", "b", 2, "a", "x y")
	if got := formatEntry(e); got != `2026-01-02T03:04:05Z INFO  hello a="x y" b=2` {
		t.Fatalf("formatEntry = %q", got)
	}
	if got := formatEntry(json.RawMessage("plain")); got != "plain" {
		t.Fatalf("non-JSON passthrough = %q", got)
	}
	for _, ok := range []string{"debug", "INFO", "Warn", "warning", "error"} {
		if _, valid := levelRank(ok); !valid {
			t.Errorf("%q should be a level", ok)
		}
	}
	if _, valid := levelRank("loud"); valid {
		t.Error("unknown level accepted")
	}
	if entryPasses(json.RawMessage(`{"level":"INFO"}`), "warn") || !entryPasses(json.RawMessage(`{"level":"ERROR"}`), "warn") {
		t.Error("level filter is wrong")
	}
	if entryPasses(json.RawMessage(`garbage`), "info") {
		t.Error("invalid JSON must not pass a level filter")
	}
}

func TestLogsCommand_RejectsBadLevel(t *testing.T) {
	testutil.TempHome(t)
	if _, _, err := runCLI(t, "logs", "--level", "loud"); err == nil || !strings.Contains(err.Error(), "--level") {
		t.Fatalf("expected a --level error, got %v", err)
	}
	stdout, _, err := runCLI(t, "logs", "--json")
	if err != nil || strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("empty log: err=%v out=%q", err, stdout.String())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
