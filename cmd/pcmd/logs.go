package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/server"
	"github.com/pocketcmd/pocketcmd-server/internal/service"
)

type logOptions struct {
	follow bool
	lines  int
	since  time.Duration
	level  string
	asJSON bool
}

var logPollInterval = 500 * time.Millisecond

func runLogs(cmd *cobra.Command, args []string) error {
	w := cmd.OutOrStdout()
	opts, err := logOptionsFrom(cmd)
	if err != nil {
		return err
	}
	if file, _ := cmd.Flags().GetString("file"); file != "" {
		return tailFile(w, file, opts, interruptChan())
	}

	db, err := stateDB()
	if err != nil {
		return err
	}
	store := server.NewLogStore(db, 10000)
	fmt.Fprint(cmd.ErrOrStderr(), journalHint())
	return logsCore(w, store, opts, interruptChan())
}

func logOptionsFrom(cmd *cobra.Command) (logOptions, error) {
	f := cmd.Flags()
	var o logOptions
	o.follow, _ = f.GetBool("follow")
	o.lines, _ = f.GetInt("lines")
	o.since, _ = f.GetDuration("since")
	o.asJSON = jsonFlag(cmd)
	if f.Lookup("level") != nil {
		level, _ := f.GetString("level")
		if level != "" {
			if _, ok := levelRank(level); !ok {
				return o, fmt.Errorf("--level %q: use debug, info, warn or error", level)
			}
			o.level = level
		}
	}
	if o.lines <= 0 {
		o.lines = 50
	}
	return o, nil
}

func interruptChan() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	return ch
}

func journalHint() string {
	if runtime.GOOS == "linux" && service.DetectInitSystem() == "systemd" {
		return "Hint: the service's stdout/stderr is in the journal: journalctl --user -u pocketcmd\n"
	}
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("Hint: the service's stdout/stderr is in %s\n", filepath.Join(config.PocketCmdDir(), "server.log"))
	}
	return ""
}

func levelRank(level string) (int, bool) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return 0, true
	case "INFO":
		return 1, true
	case "WARN", "WARNING":
		return 2, true
	case "ERROR":
		return 3, true
	}
	return 0, false
}

type entryMeta struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

func entryPasses(entry json.RawMessage, minLevel string) bool {
	if minLevel == "" {
		return true
	}
	min, _ := levelRank(minLevel)
	var m entryMeta
	if json.Unmarshal(entry, &m) != nil {
		return false
	}
	rank, ok := levelRank(m.Level)
	return ok && rank >= min
}

func formatEntry(entry json.RawMessage) string {
	var m map[string]any
	if err := json.Unmarshal(entry, &m); err != nil {
		return string(entry)
	}
	var meta entryMeta
	_ = json.Unmarshal(entry, &meta)
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == "time" || k == "level" || k == "msg" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %-5s %s", meta.Time, meta.Level, meta.Msg)
	for _, k := range keys {
		v := m[k]
		switch v := v.(type) {
		case string:
			if strings.ContainsAny(v, " \t\"") {
				fmt.Fprintf(&b, " %s=%q", k, v)
			} else {
				fmt.Fprintf(&b, " %s=%s", k, v)
			}
		default:
			raw, _ := json.Marshal(v)
			fmt.Fprintf(&b, " %s=%s", k, raw)
		}
	}
	return b.String()
}

func writeEntry(w io.Writer, entry json.RawMessage, asJSON bool) {
	if asJSON {
		fmt.Fprintln(w, string(entry))
		return
	}
	fmt.Fprintln(w, formatEntry(entry))
}

func logsCore(w io.Writer, src server.LogSource, opts logOptions, stop <-chan os.Signal) error {
	var fromMs int64
	if opts.since > 0 {
		fromMs = time.Now().Add(-opts.since).UnixMilli()
	}

	entries := tailEntries(src, opts.lines, fromMs, opts.level)
	for _, e := range entries {
		writeEntry(w, e.Entry, opts.asJSON)
	}
	if !opts.follow {
		return nil
	}

	var lastID int64
	if len(entries) > 0 {
		lastID = entries[len(entries)-1].ID
	} else {
		if newest, _, _ := src.Query(server.LogQuery{Limit: 1}); len(newest) > 0 {
			lastID = newest[0].ID
		}
	}
	ticker := time.NewTicker(logPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return errInterrupted
		case <-ticker.C:
			for _, e := range entriesAfter(src, lastID, fromMs) {
				lastID = e.ID
				if entryPasses(e.Entry, opts.level) {
					writeEntry(w, e.Entry, opts.asJSON)
				}
			}
		}
	}
}

// The level filter runs here, not in SQL, so pages are walked back until n entries match.
func tailEntries(src server.LogSource, n int, fromMs int64, level string) []server.LogEntry {
	var out []server.LogEntry
	var before int64
	for len(out) < n {
		page, _, hasMore := src.Query(server.LogQuery{Limit: n, BeforeID: before, FromMs: fromMs})
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if entryPasses(e.Entry, level) && len(out) < n {
				out = append(out, e)
			}
		}
		before = page[len(page)-1].ID
		if !hasMore {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func entriesAfter(src server.LogSource, lastID, fromMs int64) []server.LogEntry {
	var newer []server.LogEntry
	var before int64
	for {
		page, _, hasMore := src.Query(server.LogQuery{Limit: 200, BeforeID: before, FromMs: fromMs})
		if len(page) == 0 {
			break
		}
		reached := false
		for _, e := range page {
			if e.ID <= lastID {
				reached = true
				break
			}
			newer = append(newer, e)
		}
		if reached || !hasMore {
			break
		}
		before = page[len(page)-1].ID
	}
	for i, j := 0, len(newer)-1; i < j; i, j = i+1, j-1 {
		newer[i], newer[j] = newer[j], newer[i]
	}
	return newer
}

func tailFile(w io.Writer, path string, opts logOptions, stop <-chan os.Signal) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read log file: %w", err)
	}
	var sinceMs int64
	if opts.since > 0 {
		sinceMs = time.Now().Add(-opts.since).UnixMilli()
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var keep []string
	for i := len(lines) - 1; i >= 0 && len(keep) < opts.lines; i-- {
		if lines[i] == "" || !linePasses(lines[i], opts.level, sinceMs) {
			continue
		}
		keep = append(keep, lines[i])
	}
	for i := len(keep) - 1; i >= 0; i-- {
		writeEntry(w, json.RawMessage(keep[i]), opts.asJSON)
	}
	if !opts.follow {
		return nil
	}

	offset := int64(len(data))
	ticker := time.NewTicker(logPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return errInterrupted
		case <-ticker.C:
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			if fi, err := f.Stat(); err == nil && fi.Size() < offset {
				offset = 0 // rotated
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				line := sc.Text()
				offset += int64(len(line)) + 1
				if line != "" && linePasses(line, opts.level, sinceMs) {
					writeEntry(w, json.RawMessage(line), opts.asJSON)
				}
			}
			f.Close()
		}
	}
}

// With a since filter, a line without a parsable time fails closed, as the audit feed does.
func linePasses(line, level string, sinceMs int64) bool {
	if !entryPasses(json.RawMessage(line), level) {
		return false
	}
	if sinceMs == 0 {
		return true
	}
	var m entryMeta
	if json.Unmarshal([]byte(line), &m) != nil || m.Time == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, m.Time)
	return err == nil && t.UnixMilli() >= sinceMs
}
