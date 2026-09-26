package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticLogRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection.log")
	w := &rotatingLog{path: path, limit: 8}
	for _, line := range []string{"12345678", "second!!", "third"} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	previous, _ := os.ReadFile(path + ".1")
	if string(data) != "third" || string(previous) != "second!!" {
		t.Fatalf("unexpected rotation: current=%q previous=%q", data, previous)
	}
}
