package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveAPIWithDisposableAccount(t *testing.T) {
	path := os.Getenv("AES128_LIVE_QA_FILE")
	if path == "" {
		t.Skip("requires disposable live QA account")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var credentials struct{ Username, Password string }
	if err := json.Unmarshal(data, &credentials); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(credentials.Username, "aes128qa_") {
		t.Fatal("refusing non-QA account")
	}
	s := testService(t, nil)
	s.httpClient = &http.Client{Timeout: 15 * time.Second}
	var tokens []string
	t.Cleanup(func() {
		for _, token := range tokens {
			s.revokeSession(token)
		}
	})
	for i := 0; i < 3; i++ {
		result := s.Login(credentials.Username, credentials.Password)
		if !result.Success {
			t.Fatalf("live login %d failed: %s", i, result.Error)
		}
		token, err := s.readToken()
		if err != nil || token == "" {
			t.Fatal("live session not persisted")
		}
		tokens = append(tokens, token)
	}
	if s.ValidateSession() != "valid" {
		t.Fatal("live session invalid")
	}
	startup := s.StartupCheck()
	if !startup.IsLoggedIn || startup.InitialAppData.UserUUID == "" || startup.InitialAppData.UserData == nil || startup.InitialAppData.SessionName == "" {
		t.Fatal("live authenticated startup incomplete")
	}
	t.Logf("Authenticated startup: %d available locations", len(startup.InitialAppData.Locations))
	limit := s.Login(credentials.Username, credentials.Password)
	if limit.Success || len(limit.Sessions) != 3 {
		t.Fatal("live session limit contract mismatch")
	}
	for remaining := 2; remaining >= 0; remaining-- {
		result := s.DeleteSessionWithCredentials(credentials.Username, credentials.Password, 1)
		if !result.Success || len(result.Sessions) != remaining {
			t.Fatalf("delete session failed: %s", result.Error)
		}
	}
	if s.ValidateSession() != "invalid" {
		t.Fatal("revoked live session accepted")
	}
	if result := s.Login(credentials.Username, credentials.Password); !result.Success {
		t.Fatal(result.Error)
	}
	token, _ := s.readToken()
	tokens = append(tokens, token)
	t.Log("Live login, local persistence, restart refresh, session limit, deletion to empty, revoked token, and retry passed")
}
