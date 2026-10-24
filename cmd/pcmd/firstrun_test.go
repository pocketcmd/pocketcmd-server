package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestAwaitPairing_RefreshesUntilPaired(t *testing.T) {
	paired := make(chan pairedDevice, 1)
	tick := make(chan time.Time)
	refreshes := 0
	done := make(chan struct{})
	var got pairedDevice
	var outcome pairingOutcome
	go func() {
		got, outcome = awaitPairing(paired, nil, tick, nil, func() { refreshes++ })
		close(done)
	}()
	for i := 0; i < 4; i++ {
		tick <- time.Time{}
	}
	paired <- pairedDevice{name: "Pixel", id: "abc"}
	<-done

	if outcome != pairingSuccess || got.name != "Pixel" || got.id != "abc" {
		t.Fatalf("outcome %v, device %+v", outcome, got)
	}
	if refreshes != 4 {
		t.Fatalf("expected one refresh per expired token (4), got %d", refreshes)
	}
}

func TestAwaitPairing_Deadline(t *testing.T) {
	deadline := make(chan time.Time, 1)
	deadline <- time.Time{}
	_, outcome := awaitPairing(nil, nil, nil, deadline, func() { t.Fatal("no refresh expected") })
	if outcome != pairingTimedOut {
		t.Fatalf("expected pairingTimedOut, got %v", outcome)
	}
}

func TestAwaitPairing_Interrupt(t *testing.T) {
	sig := make(chan os.Signal, 1)
	sig <- syscall.SIGINT
	_, outcome := awaitPairing(nil, sig, nil, nil, func() {})
	if outcome != pairingCancelled {
		t.Fatalf("expected pairingCancelled, got %v", outcome)
	}
}

func TestAwaitPairing_NilDeadlineWaits(t *testing.T) {
	paired := make(chan pairedDevice, 1)
	done := make(chan pairingOutcome, 1)
	go func() {
		_, outcome := awaitPairing(paired, nil, nil, nil, func() {})
		done <- outcome
	}()
	select {
	case o := <-done:
		t.Fatalf("returned early with %v", o)
	case <-time.After(50 * time.Millisecond):
	}
	paired <- pairedDevice{name: "Pixel", id: "x"}
	if o := <-done; o != pairingSuccess {
		t.Fatalf("outcome %v", o)
	}
}

func TestFirstRunMode(t *testing.T) {
	cases := []struct {
		haveConfig bool
		devices    int
		want       runMode
	}{
		{false, 0, runModePair},
		{true, 0, runModePairWithConfig},
		{false, 2, runModeMigrate},
		{true, 1, runModeExisting},
	}
	for _, c := range cases {
		if got := firstRunMode(c.haveConfig, c.devices); got != c.want {
			t.Errorf("firstRunMode(%v, %d) = %v, want %v", c.haveConfig, c.devices, got, c.want)
		}
	}
}
