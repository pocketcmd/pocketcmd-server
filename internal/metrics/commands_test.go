package metrics

import (
	"testing"
)

func TestRunCommand_Echo(t *testing.T) {
	val, err := RunCommand("echo 42")
	if err != nil {
		t.Fatal(err)
	}
	if val != 42 {
		t.Fatalf("expected 42, got %f", val)
	}
}

func TestRunCommand_Percentage(t *testing.T) {
	val, err := RunCommand("echo '85.4%'")
	if err != nil {
		t.Fatal(err)
	}
	if val != 85.4 {
		t.Fatalf("expected 85.4, got %f", val)
	}
}

func TestRunCommand_WithText(t *testing.T) {
	val, err := RunCommand("echo 'connections: 123 active'")
	if err != nil {
		t.Fatal(err)
	}
	if val != 123 {
		t.Fatalf("expected 123, got %f", val)
	}
}

func TestRunCommand_Timeout(t *testing.T) {
	_, err := RunCommand("sleep 11")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestRunCommand_NoNumericOutput(t *testing.T) {
	_, err := RunCommand("echo 'no numbers here'")
	if err == nil {
		t.Fatal("expected error for non-numeric output")
	}
}

func TestValidateCommand(t *testing.T) {
	if err := ValidateCommand(""); err == nil {
		t.Fatal("empty command should fail")
	}
	if err := ValidateCommand(string(make([]byte, 5000))); err == nil {
		t.Fatal("oversized command should fail")
	}
	if err := ValidateCommand("echo hello"); err != nil {
		t.Fatalf("valid command should pass: %v", err)
	}
}
