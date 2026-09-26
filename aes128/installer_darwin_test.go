package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type installerFileInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f installerFileInfo) Name() string       { return "helper.plist" }
func (f installerFileInfo) Size() int64        { return 1 }
func (f installerFileInfo) Mode() os.FileMode  { return f.mode }
func (f installerFileInfo) ModTime() time.Time { return time.Time{} }
func (f installerFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f installerFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestInstallerDaemonTrust(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		uid   uint32
		valid bool
	}{
		{"root regular", 0644, 0, true}, {"root private", 0600, 0, true},
		{"user owned", 0644, 501, false}, {"group writable", 0664, 0, false},
		{"world writable", 0646, 0, false}, {"symlink", os.ModeSymlink | 0644, 0, false},
		{"directory", os.ModeDir | 0755, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInstallerDaemonFile(installerFileInfo{tc.mode, tc.uid})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
func TestInstallerDaemonMissingAndSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.plist")
	if installed, err := installerDaemonConfigured(path); installed || err != nil {
		t.Fatalf("missing: %v %v", installed, err)
	}
	if err := os.Symlink("/does/not/exist", path); err != nil {
		t.Fatal(err)
	}
	if installed, err := installerDaemonConfigured(path); installed || err == nil {
		t.Fatalf("symlink: %v %v", installed, err)
	}
}

func TestInstalledPackageHelperReadOnly(t *testing.T) {
	if os.Getenv("AES128_TEST_PACKAGE_HELPER") != "1" {
		t.Skip("requires pkg-installed helper")
	}
	if ok, err := installerDaemonConfigured(installerDaemonPath); !ok || err != nil {
		t.Fatalf("installation: %v %v", ok, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitForInstalledHelper(ctx); err != nil {
		t.Fatal(err)
	}
	s := &VPNService{}
	s.serviceToken, _ = s.readServiceToken()
	if err := s.connectGRPC(); err != nil {
		t.Fatal(err)
	}
	defer s.grpcConn.Close()
	status, err := s.GetCoreStatus()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(status), &result); err != nil || result.Error != "" || result.Message == "" {
		t.Fatalf("invalid status: %s (%v)", status, err)
	}
	t.Log("Root peer verified; helper status RPC passed without starting VPN")
}
