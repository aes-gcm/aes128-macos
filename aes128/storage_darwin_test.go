//go:build darwin

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDarwinStoragePrivateAndAtomic(t *testing.T) {
	t.Setenv("AES128_TEST_STORAGE", t.TempDir())
	s := &VPNService{encryptionKey: bytes.Repeat([]byte{3}, 32)}
	if err := s.saveToken("secret-session"); err != nil {
		t.Fatal(err)
	}
	p, _ := getConfigPath(tokenFileName)
	for _, path := range []string{p, filepath.Dir(p)} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm()&0077 != 0 {
			t.Fatal("storage accessible by other users")
		}
	}
	raw, _ := os.ReadFile(p)
	if bytes.Contains(raw, []byte("secret-session")) {
		t.Fatal("plaintext session")
	}
	raw[len(raw)-1] ^= 0xff
	os.WriteFile(p, raw, 0600)
	if _, err := s.readToken(); err == nil {
		t.Fatal("corruption accepted")
	}
	if kept, _ := os.ReadFile(p); !bytes.Equal(kept, raw) {
		t.Fatal("corrupt file deleted")
	}
}
func TestInstalledKeychainPersistsKey(t *testing.T) {
	if os.Getenv("AES128_TEST_KEYCHAIN") != "1" {
		t.Skip("explicit Keychain test")
	}
	first, err := getEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := getEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || !bytes.Equal(first, second) {
		t.Fatal("Keychain regenerated storage key")
	}
}

func TestCleanupNativeQASession(t *testing.T) {
	if os.Getenv("AES128_CLEANUP_NATIVE_QA") != "1" {
		t.Skip("explicit cleanup of disposable QA native session")
	}
	raw, err := os.ReadFile(os.Getenv("AES128_LIVE_QA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	var qa struct{ Username string }
	json.Unmarshal(raw, &qa)
	if !strings.HasPrefix(qa.Username, "aes128qa_") {
		t.Fatal("not a QA account")
	}
	s := &VPNService{httpClient: &http.Client{Timeout: 10 * time.Second}}
	data, err := s.LoadAppData()
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		UserData struct {
			Username string `json:"username"`
		} `json:"userData"`
	}
	json.Unmarshal([]byte(data), &saved)
	if saved.UserData.Username != qa.Username {
		t.Fatal("native session is not this test's QA account; leaving it intact")
	}
	if err := s.LogoutAndForget(); err != nil {
		t.Fatal(err)
	}
	t.Log("Removed only the disposable native session; Keychain encryption key preserved")
}
