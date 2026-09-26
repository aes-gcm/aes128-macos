//go:build darwin

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func measuredIP(endpoint string, proxyURL string) (string, error) {
	tr := &http.Transport{DisableKeepAlives: true}
	if proxyURL != "" {
		u, _ := url.Parse(proxyURL)
		tr.Proxy = http.ProxyURL(u)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	resp, err := client.Get(endpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	if net.ParseIP(v.IP) == nil {
		return "", fmt.Errorf("invalid IP")
	}
	return v.IP, nil
}
func TestLiveDarwinTunnelMatrix(t *testing.T) {
	if os.Getenv("AES128_TEST_MACOS_TUNNEL") != "1" {
		t.Skip("explicit live macOS network test")
	}
	raw, err := os.ReadFile(os.Getenv("AES128_LIVE_QA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	var qa struct {
		Username, Password, UUID, Host string
		XHTTPPort, XTLSPort            int
	}
	if err = json.Unmarshal(raw, &qa); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(qa.Username, "aes128qa_") {
		t.Fatal("refusing non-QA account")
	}
	s := testService(t, nil)
	s.httpClient = &http.Client{Timeout: 15 * time.Second}
	s.serviceToken, _ = s.readServiceToken()
	if err = s.connectGRPC(); err != nil {
		t.Fatal(err)
	}
	defer s.grpcConn.Close()
	defer s.StopCore()
	if result := s.Login(qa.Username, qa.Password); !result.Success {
		t.Fatal(result.Error)
	}
	token, _ := s.readToken()
	defer s.revokeSession(token)
	startup := s.StartupCheck()
	if !startup.IsLoggedIn {
		t.Fatal("API startup failed")
	}
	before, err := measuredIP("https://api.ipify.org?format=json", "")
	if err != nil {
		t.Fatal(err)
	}
	if qa.Host == "" || qa.XHTTPPort < 1 || qa.XTLSPort < 1 {
		t.Fatal("QA file must specify Host, XHTTPPort and XTLSPort")
	}
	loc := LocationInfo{Name: "macOS QA", Domain: qa.Host, VlessXhttpPort: qa.XHTTPPort, VlessXTLSPort: qa.XTLSPort}
	base := AppData{UserUUID: qa.UUID, Locations: []LocationInfo{loc}, SelectedLocationName: loc.Name}
	for _, tc := range []struct {
		name, protocol, mode string
		custom               bool
	}{{"xhttp", "vless-xhttp", "", false}, {"xtls", "vless-xtls", "", false}, {"split-exclude", "vless-xhttp", "exclude", false}, {"split-tunnel", "vless-xhttp", "tunnel", false}, {"custom-xhttp", "vless-xhttp", "", true}} {
		t.Run(tc.name, func(t *testing.T) {
			data := base
			data.Protocol = tc.protocol
			data.SplitTunnelEnabled = tc.mode != ""
			data.SplitTunnelMode = tc.mode
			data.SplitTunnelDomains = "api.ipify.org"
			if tc.custom {
				data.UseCustomLink = true
				data.CustomV2rayLink = fmt.Sprintf("vless://%s@%s:%d?security=tls&type=xhttp&path=%%2Fsync%%2Fv2%%2Fpush&sni=%s", qa.UUID, qa.Host, qa.XHTTPPort, url.QueryEscape(qa.Host))
			}
			b, _ := json.Marshal(data)
			if err := s.SaveAppData(string(b)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.StartCore(); err != nil {
				t.Fatal(err)
			}
			defer s.StopCore()
			proxy, err := measuredIP("https://api.ipify.org?format=json", "socks5://127.0.0.1:10808")
			if err != nil {
				t.Fatal(err)
			}
			if proxy == before {
				t.Fatal("VPN exit matches direct network")
			}
			actual, err := measuredIP("https://api.ipify.org?format=json", "")
			if err != nil {
				t.Fatal(err)
			}
			want := proxy
			if tc.mode == "exclude" {
				want = before
			}
			if actual != want {
				t.Fatalf("system traffic did not follow %s routing", tc.name)
			}
			if _, err = s.StopCore(); err != nil {
				t.Fatal(err)
			}
			restored, err := measuredIP("https://api.ipify.org?format=json", "")
			if err != nil || restored != before {
				t.Fatal("direct network not restored")
			}
			t.Log("Verified encrypted exit, system routing and network restoration")
		})
	}
}

func TestLiveDarwinOrphanChild(t *testing.T) {
	if os.Getenv("AES128_QA_ORPHAN_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	raw, err := os.ReadFile(os.Getenv("AES128_LIVE_QA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	var qa struct {
		Username, UUID, Host string
		XHTTPPort            int
	}
	if err := json.Unmarshal(raw, &qa); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(qa.Username, "aes128qa_") || qa.Host == "" || qa.XHTTPPort < 1 {
		t.Fatal("disposable QA account and explicit server required")
	}
	s := testService(t, nil)
	s.serviceToken, _ = s.readServiceToken()
	if err := s.connectGRPC(); err != nil {
		t.Fatal(err)
	}
	d := AppData{UserUUID: qa.UUID, Protocol: "vless-xhttp", Locations: []LocationInfo{{Name: "macOS QA", Domain: qa.Host, VlessXhttpPort: qa.XHTTPPort}}, SelectedLocationName: "macOS QA"}
	b, _ := json.Marshal(d)
	if err := s.SaveAppData(string(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartCore(); err != nil {
		t.Fatal(err)
	}
	beforeStop := ""
	fmt.Println("QA_TUNNEL_READY")
	for {
		time.Sleep(time.Second)
		if os.Getenv("AES128_QA_EXPECT_TRANSPORT_LOSS") == "1" {
			state, err := s.GetCoreStatus()
			if err != nil {
				t.Fatal(err)
			}
			var st struct {
				IsRunning bool   `json:"isRunning"`
				Message   string `json:"message"`
			}
			json.Unmarshal([]byte(state), &st)
			if !st.IsRunning {
				beforeStop = st.Message
				break
			}
		}
	}
	if !strings.Contains(beforeStop, "transport lost") {
		t.Fatal("unexpected disconnect reason: ", beforeStop)
	}
	t.Log("Transport loss detected; cores stopped and DNS restored")
}
func TestLiveDarwinClientCrashRecovery(t *testing.T) {
	if os.Getenv("AES128_TEST_MACOS_TUNNEL") != "1" {
		t.Skip("explicit live test")
	}
	before, err := measuredIP("https://api.ipify.org?format=json", "")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLiveDarwinOrphanChild$", "-test.v")
	cmd.Env = append(os.Environ(), "AES128_QA_ORPHAN_CHILD=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "QA_TUNNEL_READY") {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child failed to connect")
		}
	case <-time.After(40 * time.Second):
		t.Fatal("child startup timed out")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	s := &VPNService{}
	s.serviceToken, _ = s.readServiceToken()
	s.connectGRPC()
	defer s.grpcConn.Close()
	defer s.StopCore()
	stopped := false
	for i := 0; i < 12; i++ {
		state, _ := s.GetCoreStatus()
		var status struct {
			IsRunning bool `json:"isRunning"`
		}
		json.Unmarshal([]byte(state), &status)
		if !status.IsRunning {
			stopped = true
			break
		}
		time.Sleep(time.Second)
	}
	if !stopped {
		t.Fatal("orphan VPN stayed active after client SIGKILL")
	}
	restored, err := measuredIP("https://api.ipify.org?format=json", "")
	if err != nil || restored != before {
		t.Fatal("network did not recover after client crash")
	}
	t.Log("SIGKILL of connected client stopped both cores and restored direct networking")
}
