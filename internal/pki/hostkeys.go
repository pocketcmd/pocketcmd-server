package pki

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

func MachineSSHHostKeyFingerprints() []string {
	matches, _ := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	more, _ := filepath.Glob("/etc/ssh/ssh_host_*.pub")
	seen := map[string]bool{}
	out := []string{} // never nil: the wire shape is an array
	for _, path := range append(matches, more...) {
		if seen[path] {
			continue
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		fp, ok := FingerprintAuthorizedKey(string(data))
		if ok && !containsString(out, fp) {
			out = append(out, fp)
		}
	}
	return out
}

func FingerprintAuthorizedKey(line string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(blob)
	return base64.RawStdEncoding.EncodeToString(sum[:]), true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
