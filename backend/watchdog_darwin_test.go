package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdleWatchdogRetriesFailedDNSRecovery(t *testing.T) {
	oldPath, oldSetup := dnsJournalPath, networkSetup
	t.Cleanup(func() { dnsJournalPath = oldPath; networkSetup = oldSetup })
	dnsJournalPath = filepath.Join(t.TempDir(), "dns.json")
	if err := writeDNSJournal([]dnsEntry{{Service: "Wi-Fi"}}); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	networkSetup = func(args ...string) ([]byte, error) {
		if args[0] == "-getdnsservers" {
			return []byte("10.99.0.2"), nil
		}
		if attempts.Add(1) == 1 {
			return nil, errors.New("temporary failure")
		}
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	s := &vpnControlServer{}
	go func() { defer close(done); s.watchTicks(ctx, ticks) }()
	defer func() { cancel(); <-done }()
	for i := 0; i < 11; i++ {
		select {
		case ticks <- time.Now():
		case <-time.After(5 * time.Second):
			t.Fatal("watchdog stalled")
		}
	}
	if attempts.Load() != 2 {
		t.Fatalf("DNS recovery attempts = %d, want 2", attempts.Load())
	}
	if _, err := os.Stat(dnsJournalPath); !os.IsNotExist(err) {
		t.Fatalf("recovery journal retained after success: %v", err)
	}
}
