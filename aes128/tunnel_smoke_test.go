package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestInstalledTunnelReconnect(t *testing.T) {
	if os.Getenv("AES128_TEST_TUNNEL") != "1" {
		t.Skip("requires explicit live tunnel test")
	}
	s := &VPNService{ipClient: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
	var err error
	s.serviceToken, err = s.readServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.connectGRPC(); err != nil {
		t.Fatal(err)
	}
	defer s.grpcConn.Close()
	defer s.StopCore()
	if _, err := s.StopCore(); err != nil {
		t.Fatal(err)
	}
	data, err := s.LoadAppData()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(data), &s.appData); err != nil {
		t.Fatal(err)
	}
	direct := s.GetMyIP()
	if direct.Query == "" {
		t.Fatal("could not verify direct connectivity")
	}
	if _, err := s.StartCore(); err != nil {
		t.Fatal(err)
	}
	verified := false
	for i := 0; i < 3; i++ {
		info := freshIPCheck()
		if info.Query != "" && info.Query != direct.Query {
			verified = true
			break
		}
		time.Sleep(time.Second)
	}
	if !verified {
		t.Fatal("public IP did not change after reconnect")
	}
	if _, err := s.StopCore(); err != nil {
		t.Fatal(err)
	}
	status, err := s.GetCoreStatus()
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		IsRunning bool `json:"isRunning"`
	}
	json.Unmarshal([]byte(status), &state)
	if state.IsRunning {
		t.Fatal("VPN processes remained active after disconnect")
	}
	restored := s.GetMyIP()
	if restored.Query != direct.Query {
		t.Fatal("direct network was not restored after disconnect")
	}
	t.Log("Live XHTTP reconnect changed public IP; disconnect restored direct IP and stopped both cores")
}
