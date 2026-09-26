package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestInstalledServiceRPCAndStorage(t *testing.T) {
	if os.Getenv("AES128_TEST_INSTALLED") != "1" {
		t.Skip("requires an installed Windows service")
	}
	t.Setenv("ProgramData", t.TempDir())
	t.Setenv("AES128_TEST_STORAGE", os.Getenv("ProgramData"))
	s := &VPNService{}
	token, err := s.readServiceToken()
	if err != nil || token == "" {
		t.Fatal("installed service token unavailable")
	}
	s.serviceToken = token
	if err := s.connectGRPC(); err != nil {
		t.Fatal(err)
	}
	defer s.grpcConn.Close()
	status, err := s.GetCoreStatus()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		IsRunning bool   `json:"isRunning"`
		Message   string `json:"message"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal([]byte(status), &result); err != nil || result.Error != "" || result.Message == "" {
		t.Fatal("installed service status RPC failed")
	}
	if err := s.saveToken("local-smoke-test-only"); err != nil {
		t.Fatal(err)
	}
	if token, err := s.readToken(); err != nil || token != "local-smoke-test-only" {
		t.Fatal("installed key cannot persist sessions")
	}
	t.Log("Installed service authentication and encrypted session storage passed")
}
