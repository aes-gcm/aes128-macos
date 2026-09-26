package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func testService(t *testing.T, handler roundTripFunc) *VPNService {
	t.Helper()
	t.Setenv("ProgramData", t.TempDir())
	t.Setenv("AES128_TEST_STORAGE", os.Getenv("ProgramData"))
	return &VPNService{encryptionKey: bytes.Repeat([]byte{7}, 32), httpClient: &http.Client{Transport: handler}, ipClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, `{"ip":"192.0.2.1"}`), nil })}}
}

func TestLoginPersistsEncryptedSession(t *testing.T) {
	s := testService(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://client.aes.cx/api/app/login" {
			t.Errorf("unexpected login URL %s", r.URL)
		}
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["username"] != "new-user" || payload["password"] != " password " {
			t.Errorf("credentials normalization changed password")
		}
		return response(200, `{"app_session_token":"test-session","session_name":"New device"}`), nil
	})
	if result := s.Login(" new-user ", " password "); !result.Success {
		t.Fatal(result.Error)
	}
	path, _ := getConfigPath(tokenFileName)
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("test-session")) {
		t.Fatal("token saved in plaintext")
	}
	restarted := &VPNService{encryptionKey: s.encryptionKey}
	if token, err := restarted.readToken(); err != nil || token != "test-session" {
		t.Fatalf("restart: %q %v", token, err)
	}
}

func TestLoginRejectsMissingToken(t *testing.T) {
	s := testService(t, func(*http.Request) (*http.Response, error) { return response(200, `{}`), nil })
	if result := s.Login("user", "password"); result.Success {
		t.Fatal("accepted empty session")
	}
	if token, _ := s.readToken(); token != "" {
		t.Fatal("stored invalid token")
	}
}

func TestStorageFailureDoesNotConsumeSession(t *testing.T) {
	calls := 0
	s := testService(t, func(*http.Request) (*http.Response, error) { calls++; return response(200, `{}`), nil })
	if err := os.WriteFile(filepath.Join(os.Getenv("ProgramData"), "AES128 VPN"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	result := s.Login("user", "password")
	if result.Success || calls != 0 {
		t.Fatalf("login reached server with unusable storage: %d calls", calls)
	}
}

func TestFailedTokenWriteReleasesServerSession(t *testing.T) {
	revoked := false
	s := testService(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/logout") {
			revoked = r.Header.Get("X-App-Session-Token") == "unsaved"
			return response(200, `{}`), nil
		}
		return response(200, `{"app_session_token":"unsaved"}`), nil
	})
	path, _ := getConfigPath(tokenFileName)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if result := s.Login("user", "password"); result.Success || !revoked {
		t.Fatalf("failed login did not release session: revoked=%v", revoked)
	}
}

func TestSessionLimitAndNullSessionList(t *testing.T) {
	s := testService(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/delete-session") {
			return response(200, `{"status":"success","sessions":null}`), nil
		}
		return response(409, `{"error":"Maximum number of app sessions reached.","sessions":[{"id":1,"name":"Device"}]}`), nil
	})
	result := s.Login("user", "password")
	if result.Success || len(result.Sessions) != 1 {
		t.Fatalf("unexpected limit result: %+v", result)
	}
	if result := s.DeleteSessionWithCredentials("user", "password", 1); !result.Success || len(result.Sessions) != 0 {
		t.Fatal(result)
	}
}

func TestStartupMergesSuccessfulEndpoints(t *testing.T) {
	for _, settingsBody := range []string{"server error", "{malformed"} {
		t.Run(settingsBody, func(t *testing.T) {
			s := testService(t, func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("X-App-Session-Token") != "cached" {
					t.Error("missing session header")
				}
				switch r.URL.Path {
				case "/api/app/settings":
					if settingsBody == "server error" {
						return response(503, settingsBody), nil
					}
					return response(200, settingsBody), nil
				case "/api/app/account_info":
					return response(200, `{"status":"valid","user":{"username":"new-user"}}`), nil
				case "/api/app/locations":
					return response(200, `{"user_uuid":"new-uuid","locations":[{"name":"New location","domain":"vpn.example","vless_xhttp_port":443}]}`), nil
				default:
					return response(200, `{"session_name":"Updated device"}`), nil
				}
			})
			s.saveToken("cached")
			s.SaveAppData(`{"latestAppVersion":"1.0.0","user_uuid":"old-uuid"}`)
			result := s.StartupCheck()
			if !result.IsLoggedIn || result.InitialAppData.UserUUID != "new-uuid" || result.InitialAppData.LatestAppVersion != "1.0.0" || result.IsUpdateAvailable {
				t.Fatalf("partial refresh failed: %+v", result)
			}
		})
	}
}

func TestValidationKeepsSessionOnNetworkFailure(t *testing.T) {
	for _, code := range []int{200, 401, 403, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s := testService(t, func(*http.Request) (*http.Response, error) { return response(code, `{}`), nil })
			s.saveToken("valid-token")
			want := "unknown"
			if code == 200 {
				want = "valid"
			}
			if code == 401 || code == 403 {
				want = "invalid"
			}
			if got := s.ValidateSession(); got != want {
				t.Fatalf("got %s want %s", got, want)
			}
		})
	}
}

func TestConcurrentAtomicSettingsWrites(t *testing.T) {
	s := testService(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.SaveAppData(fmt.Sprintf(`{"protocol":"vless-xhttp","sessionName":"%d"}`, i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	data, err := s.LoadAppData()
	if err != nil || !json.Valid([]byte(data)) {
		t.Fatalf("invalid encrypted cache %v", err)
	}
	if err := s.SaveAppData(`{bad`); err == nil {
		t.Fatal("accepted malformed settings")
	}
	after, _ := s.LoadAppData()
	if after != data {
		t.Fatal("malformed settings replaced valid cache")
	}
}

func TestCorruptSessionIsPreservedForRecovery(t *testing.T) {
	s := testService(t, nil)
	path, _ := getConfigPath(tokenFileName)
	os.WriteFile(path, []byte("corrupt"), 0600)
	if _, err := s.readToken(); err == nil {
		t.Fatal("accepted corrupt token")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("destroyed recoverable session file")
	}
}

func TestVersionComparison(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{{"1.0.0", "1.0.1", false}, {"1.0.2", "1.0.1", true}, {"1.10.0", "1.9.0", true}, {"v2.0.0", "1.0.1", true}, {"garbage", "1.0.1", false}, {"1.0.1", "1.0.1", false}} {
		if got := isNewerVersion(c.latest, c.current); got != c.want {
			t.Errorf("%s vs %s: %v", c.latest, c.current, got)
		}
	}
}

func TestLocationsRespectProtocolAndTor(t *testing.T) {
	data := AppData{Locations: []LocationInfo{{Name: "XHTTP", VlessXhttpPort: 443}, {Name: "XTLS", VlessXTLSPort: 8443}, {Name: "Tor", VlessXTLSTorPort: 9443}}}
	for _, check := range []struct {
		protocol string
		tor      bool
		want     string
	}{{"vless-xhttp", false, "XHTTP"}, {"vless-xtls", false, "XTLS"}, {"vless-xhttp", true, "Tor"}} {
		data.Protocol = check.protocol
		data.EnableTor = check.tor
		locations := compatibleLocations(data)
		if len(locations) != 1 || locations[0].Name != check.want {
			t.Fatalf("incompatible server selection: %+v", locations)
		}
	}
}
