package metrics

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRunCommand_KillsWholePipelineGroup(t *testing.T) {
	marker := "pcmdleakprobe"
	start := time.Now()
	_, err := RunCommand("top | grep " + marker)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 13*time.Second {
		t.Fatalf("took %v, expected ~10s timeout", elapsed)
	}
	time.Sleep(500 * time.Millisecond)
	out, _ := exec.Command("pgrep", "-fl", marker).Output()
	if survivors := strings.TrimSpace(string(out)); survivors != "" {
		t.Fatalf("pipeline members survived the group kill:\n%s", survivors)
	}
}
