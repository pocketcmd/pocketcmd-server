package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func noServer(t *testing.T) *fakeService {
	t.Helper()
	f := &fakeService{}
	f.bind(t)
	return f
}

func writeArchive(t *testing.T, files map[string]string, extra func(tw *tar.Writer)) string {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	tw.Close()
	gw.Close()
	p := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

var minimalBackup = map[string]string{
	".pocketcmd/state.db":       "db",
	".pocketcmd/tls/server.key": "key",
}

func TestBackupRestore_RoundTrip(t *testing.T) {
	testutil.TempHome(t)
	noServer(t)
	dir := config.PocketCmdDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}

	db, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO users (user_id, display_name, role, created_at) VALUES ('u1','Alice','admin','now')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"service_mode":"foreground"}`), 0600); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "tls"), 0700)
	if err := os.WriteFile(filepath.Join(dir, "tls", "server.key"), []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := backupCore(io.Discard, archive); err != nil {
		t.Fatalf("backup: %v", err)
	}

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := restoreCore(io.Discard, archive, 8767, "127.0.0.1", true, true); err != nil {
		t.Fatalf("restore: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || string(got) != `{"service_mode":"foreground"}` {
		t.Fatalf("config not restored: %q err=%v", got, err)
	}
	rdb, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	var n int
	if err := rdb.QueryRow("SELECT COUNT(*) FROM users WHERE user_id='u1'").Scan(&n); err != nil {
		t.Fatalf("query restored db: %v", err)
	}
	if n != 1 {
		t.Fatalf("restored db missing row: got %d", n)
	}
}

func TestBackup_SurvivesStaleSidecars(t *testing.T) {
	testutil.TempHome(t)
	dir := config.PocketCmdDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	// state.Open uses WAL; create the sidecars by hand so they exist whatever the driver left behind.
	for _, name := range []string{"state.db-wal", "state.db-shm", "metrics.db-shm"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := backupCore(io.Discard, archive); err != nil {
		t.Fatalf("backup with stale sidecars: %v", err)
	}

	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	names := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[filepath.Base(h.Name)] = true
	}
	if !names["state.db"] {
		t.Fatalf("state.db missing from archive: %v", names)
	}
	for n := range names {
		if filepath.Ext(n) == ".db-wal" || filepath.Ext(n) == ".db-shm" {
			t.Fatalf("sidecar %s must not be archived", n)
		}
	}
}

func TestRestore_RejectsTraversalAndClampsMode(t *testing.T) {
	testutil.TempHome(t)
	noServer(t)
	dir := config.PocketCmdDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Dir(dir)

	hostile := []struct {
		name  string
		entry func(tw *tar.Writer)
	}{
		{"sibling prefix", func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: ".pocketcmd-evil/escape.txt", Mode: 0600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}},
		{"parent traversal", func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: ".pocketcmd/../escape2.txt", Mode: 0600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}},
		{"symlink", func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: ".pocketcmd/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
		}},
	}
	for _, h := range hostile {
		archive := writeArchive(t, minimalBackup, h.entry)
		err := restoreCore(io.Discard, archive, 8767, "127.0.0.1", true, true)
		if err == nil || !strings.Contains(err.Error(), "invalid backup") {
			t.Errorf("%s: expected an invalid-backup error, got %v", h.name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "state.db")); !os.IsNotExist(err) {
			t.Errorf("%s: a refused archive must not be extracted at all", h.name)
		}
	}
	for _, p := range []string{
		filepath.Join(home, ".pocketcmd-evil", "escape.txt"),
		filepath.Join(home, "escape2.txt"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("path-traversal escape wrote %s (err=%v)", p, err)
		}
	}

	archive := writeArchive(t, minimalBackup, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: ".pocketcmd/legit.txt", Mode: 0777, Size: 2, Typeflag: tar.TypeReg})
		tw.Write([]byte("ok"))
	})
	if err := restoreCore(io.Discard, archive, 8767, "127.0.0.1", true, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "legit.txt"))
	if err != nil {
		t.Fatalf("legit file not restored: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("mode not clamped: got %o want 0600", fi.Mode().Perm())
	}
}

func TestRestore_RequiresStateAndKey(t *testing.T) {
	testutil.TempHome(t)
	noServer(t)

	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no state.db", map[string]string{".pocketcmd/tls/server.key": "k"}, "state.db is missing"},
		{"no server.key", map[string]string{".pocketcmd/state.db": "db"}, "server.key is missing"},
		{"empty", map[string]string{}, "empty"},
	}
	for _, c := range cases {
		archive := writeArchive(t, c.files, nil)
		err := restoreCore(io.Discard, archive, 8767, "127.0.0.1", true, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
	notGzip := filepath.Join(t.TempDir(), "x.tar.gz")
	os.WriteFile(notGzip, []byte("hello"), 0600)
	if err := restoreCore(io.Discard, notGzip, 8767, "127.0.0.1", true, true); err == nil || !strings.Contains(err.Error(), "not gzip") {
		t.Errorf("plain file: %v", err)
	}
	if err := restoreCore(io.Discard, filepath.Join(t.TempDir(), "missing.tar.gz"), 8767, "127.0.0.1", true, true); err == nil || !strings.Contains(err.Error(), "open backup") {
		t.Errorf("missing file: %v", err)
	}
}

func TestRestore_RefusesWhileServerRuns(t *testing.T) {
	testutil.TempHome(t)
	f := noServer(t)
	archive := writeArchive(t, minimalBackup, nil)

	f.installed, f.running = true, true
	err := restoreCore(io.Discard, archive, 8767, "127.0.0.1", true, true)
	if err == nil || !strings.Contains(err.Error(), "pcmd stop") {
		t.Fatalf("running service: %v", err)
	}

	f.installed, f.running, f.healthy = false, true, true
	err = restoreCore(io.Discard, archive, 8767, "127.0.0.1", true, true)
	if err == nil || !strings.Contains(err.Error(), "listening on port 8767") {
		t.Fatalf("foreground server: %v", err)
	}
	if _, err := os.Stat(filepath.Join(config.PocketCmdDir(), "state.db")); !os.IsNotExist(err) {
		t.Fatal("nothing may be restored while a server runs")
	}

	f.running, f.healthy = false, false
	if err := restoreCore(io.Discard, archive, 8767, "127.0.0.1", true, true); err != nil {
		t.Fatalf("restore with nothing running: %v", err)
	}
}

func TestArchiveRel(t *testing.T) {
	good := map[string]string{".pocketcmd": ".", ".pocketcmd/": ".", ".pocketcmd/state.db": "state.db", ".pocketcmd/tls/server.key": filepath.Join("tls", "server.key"), ".pocketcmd/a/../b": "b"}
	for name, want := range good {
		if got, err := archiveRel(name); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", name, got, err, want)
		}
	}
	for _, bad := range []string{"state.db", ".pocketcmd-evil/x", ".pocketcmd/../x", ".pocketcmd/a/../../x", "/etc/passwd", "../.pocketcmd/x"} {
		if _, err := archiveRel(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestBackup_ArchiveIsOwnerOnly(t *testing.T) {
	testutil.TempHome(t)
	dir := config.PocketCmdDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	oldMask := syscall.Umask(0)
	defer syscall.Umask(oldMask)

	newDir := filepath.Join(t.TempDir(), "nested", "backups")
	archive := filepath.Join(newDir, "pc.tar.gz")
	if err := backupCore(io.Discard, archive); err != nil {
		t.Fatalf("backup: %v", err)
	}
	fi, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("archive mode %o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(newDir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0700 {
		t.Fatalf("created backup dir mode %o, want 0700", di.Mode().Perm())
	}

	if err := os.Chmod(archive, 0644); err != nil {
		t.Fatal(err)
	}
	if err := backupCore(io.Discard, archive); err != nil {
		t.Fatalf("backup over existing: %v", err)
	}
	fi, _ = os.Stat(archive)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("re-created archive mode %o, want 0600", fi.Mode().Perm())
	}
}
