package main

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
)

// A restored archive may be untrusted, so the extracted size is capped.
const maxRestoreBytes = 4 << 30

func runBackup(cmd *cobra.Command, args []string) error {
	outPath := fmt.Sprintf("pocketcmd-backup-%s.tar.gz", time.Now().Format("2006-01-02"))
	if len(args) > 0 {
		outPath = args[0]
	}
	return backupCore(cmd.OutOrStdout(), outPath)
}

func backupCore(w io.Writer, outPath string) error {
	srcDir := config.PocketCmdDir()
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		return fmt.Errorf("nothing to backup: %s does not exist", srcDir)
	}

	// The archive holds server.key and state.db; it must never be the one world-readable copy.
	if dir := filepath.Dir(outPath); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create backup directory: %w", err)
		}
	}
	file, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	defer file.Close()
	// O_CREATE's mode applies only to a new file; an existing looser archive must be tightened too.
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict backup file: %w", err)
	}

	gw := gzip.NewWriter(file)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	tmpSnaps := map[string]string{}
	defer func() {
		for _, p := range tmpSnaps {
			os.RemoveAll(filepath.Dir(p))
		}
	}()

	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		// Skip sidecars before looking at err: snapshotDB removes -wal/-shm after Walk listed them, so lstat fails with ENOENT.
		if strings.HasSuffix(path, ".corrupt") || strings.HasSuffix(path, ".bak") ||
			strings.HasSuffix(path, ".db-wal") || strings.HasSuffix(path, ".db-shm") {
			return nil
		}
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(srcDir, path)
		content := path
		if !info.IsDir() && strings.HasSuffix(path, ".db") {
			snap, snapErr := snapshotDB(path)
			if snapErr != nil {
				return fmt.Errorf("snapshot %s: %w", relPath, snapErr)
			}
			tmpSnaps[path] = snap
			content = snap
			if info, err = os.Stat(snap); err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.Join(".pocketcmd", relPath)
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		f, err := os.Open(content)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		os.Remove(outPath)
		return fmt.Errorf("backup failed: %w", err)
	}

	fmt.Fprintf(w, "Backup saved to %s\n", outPath)
	return nil
}

func snapshotDB(dbPath string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "pcmd-snap")
	if err != nil {
		return "", err
	}
	dst := filepath.Join(tmpDir, "snapshot.db") // must not pre-exist for VACUUM INTO

	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}
	defer db.Close()
	if _, err := db.Exec("VACUUM INTO '" + strings.ReplaceAll(dst, "'", "''") + "'"); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}
	return dst, nil
}

func runRestore(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")
	yes, nonInteractive := guardFlags(cmd)
	port, host, _ := runtimeSettings(cmd)
	return restoreCore(cmd.OutOrStdout(), args[0], port, host, yes || force, nonInteractive)
}

const archivePrefix = ".pocketcmd/"

// The trailing slash in the prefix check also rejects the sibling-prefix trick (.pocketcmd-evil/).
func archiveRel(name string) (string, error) {
	slash := filepath.ToSlash(name)
	if slash == ".pocketcmd" || slash == archivePrefix {
		return ".", nil
	}
	if !strings.HasPrefix(slash, archivePrefix) {
		return "", fmt.Errorf("entry %q is outside the %s directory", name, strings.TrimSuffix(archivePrefix, "/"))
	}
	rel := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(slash, archivePrefix)))
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("entry %q escapes the %s directory", name, strings.TrimSuffix(archivePrefix, "/"))
	}
	return rel, nil
}

func validateBackupArchive(backupPath string) error {
	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer file.Close()
	gr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("invalid backup (not gzip): %w", err)
	}
	defer gr.Close()

	required := map[string]bool{"state.db": false, filepath.Join("tls", "server.key"): false}
	tr := tar.NewReader(gr)
	entries := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid backup (not a tar archive): %w", err)
		}
		entries++
		rel, err := archiveRel(header.Name)
		if err != nil {
			return fmt.Errorf("invalid backup: %w", err)
		}
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
		default:
			return fmt.Errorf("invalid backup: entry %q is not a regular file or directory", header.Name)
		}
		if _, ok := required[rel]; ok && header.Typeflag == tar.TypeReg {
			required[rel] = true
		}
	}
	if entries == 0 {
		return fmt.Errorf("invalid backup: the archive is empty")
	}
	for _, name := range []string{"state.db", filepath.Join("tls", "server.key")} {
		if !required[name] {
			return fmt.Errorf("invalid backup: %s is missing (not a pcmd backup?)", name)
		}
	}
	return nil
}

func restoreCore(w io.Writer, backupPath string, port int, host string, yes, nonInteractive bool) error {
	destDir := config.PocketCmdDir()

	if err := validateBackupArchive(backupPath); err != nil {
		return err
	}

	// Never extract over a live database: the server holds WAL handles.
	if svc.isInstalled() && svc.status().Running {
		return fmt.Errorf("the service is running; run 'pcmd stop' before restoring")
	}
	if svc.healthCheck(host, port) == nil {
		return fmt.Errorf("a server is listening on port %d; stop it before restoring (Ctrl+C the foreground server, or 'pcmd stop')", port)
	}

	if _, err := os.Stat(destDir); err == nil {
		ok, err := confirmDestructive(w, "overwrite "+destDir,
			fmt.Sprintf("%s already exists. Overwrite it with the backup?", destDir), yes, nonInteractive)
		if err != nil || !ok {
			return err
		}
	}

	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("invalid backup (not gzip): %w", err)
	}
	defer gr.Close()

	destRoot := filepath.Clean(destDir)
	tr := tar.NewReader(gr)
	count := 0
	var total int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read backup: %w", err)
		}
		// Re-checked so extraction never writes outside destRoot even if the file changed since validation.
		rel, err := archiveRel(header.Name)
		if err != nil {
			return fmt.Errorf("invalid backup: %w", err)
		}
		target := filepath.Join(destRoot, rel)
		if r, err := filepath.Rel(destRoot, target); err != nil ||
			r == ".." || strings.HasPrefix(r, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("invalid backup: entry %q escapes the state directory", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0700)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0700)
			// Clamp the mode rather than trusting the header; a hostile archive must not drop a world-readable server.key.
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("restore file %s: %w", rel, err)
			}
			n, err := io.Copy(f, io.LimitReader(tr, maxRestoreBytes-total))
			f.Close()
			if err != nil {
				return fmt.Errorf("restore file %s: %w", rel, err)
			}
			total += n
			if total >= maxRestoreBytes {
				return fmt.Errorf("restore aborted: archive exceeds %d bytes", maxRestoreBytes)
			}
			count++
		}
	}

	fmt.Fprintf(w, "Restored %d files to %s\n", count, destDir)
	return nil
}
