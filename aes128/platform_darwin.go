package main

/*
#cgo LDFLAGS: -framework Security -framework Foundation -framework ServiceManagement
#include <stdlib.h>
int aesKeychain(unsigned char *key);
char *aesRegisterHelper(void);
char *aesUnregisterHelper(void);
char *aesAutoStart(int enabled);
int aesAutoStartStatus(void);
*/
import "C"
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const helperSocket = "/var/run/com.aes128.vpn/control.sock"
const serviceGRPCAddr = "unix://" + helperSocket

func getEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if code := C.aesKeychain((*C.uchar)(unsafe.Pointer(&key[0]))); code != 0 {
		return nil, fmt.Errorf("Keychain error %d; existing key was not replaced", int(code))
	}
	return key, nil
}
func getConfigPath(name string) (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(os.Args[0], ".test") && os.Getenv("AES128_TEST_STORAGE") != "" {
		base = os.Getenv("AES128_TEST_STORAGE")
	}
	dir := filepath.Join(base, "AES128 VPN")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}
func (s *VPNService) readServiceToken() (string, error) { return "unix-peer-credentials", nil }
func platformDialOption() grpc.DialOption {
	return grpc.WithContextDialer(dialPlatformHelper)
}
func dialPlatformHelper(ctx context.Context, _ string) (net.Conn, error) {
	st, err := os.Lstat(helperSocket)
	if err != nil {
		return nil, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode()&os.ModeSocket == 0 || stat.Uid != 0 {
		return nil, errors.New("untrusted helper socket")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", helperSocket)
	if err != nil {
		return nil, err
	}
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}
	var cred *unix.Xucred
	var credErr error
	err = raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) })
	if err != nil || credErr != nil || cred == nil || cred.Uid != 0 {
		conn.Close()
		return nil, errors.New("helper is not privileged")
	}
	return conn, nil
}

const installerDaemonPath = "/Library/LaunchDaemons/com.aes128.vpn.helper.plist"

func validateInstallerDaemonFile(st os.FileInfo) error {
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || stat.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("untrusted VPN service installation; reinstall AES128 VPN")
	}
	return nil
}

func installerDaemonConfigured(path string) (bool, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := validateInstallerDaemonFile(st); err != nil {
		return false, err
	}
	return true, nil
}

func waitForInstalledHelper(ctx context.Context) error {
	var lastErr error
	for {
		conn, err := dialPlatformHelper(ctx, serviceGRPCAddr)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("VPN service is unavailable; reinstall AES128 VPN to repair it (if you disabled its background service, allow it in System Settings): %w", lastErr)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (s *VPNService) platformStartContext(ctx context.Context) context.Context {
	s.dataLock.RLock()
	data, _ := json.Marshal(s.appData)
	s.dataLock.RUnlock()
	return metadata.AppendToOutgoingContext(ctx, "aes128-config-bin", string(data))
}
func nativeError(message *C.char) error {
	if message == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(message))
	return errors.New(C.GoString(message))
}
func (s *VPNService) ensureServiceIsRunning() error {
	installed, err := installerDaemonConfigured(installerDaemonPath)
	if err != nil {
		return err
	}
	if installed {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return waitForInstalledHelper(ctx)
	}

	if err := nativeError(C.aesRegisterHelper()); err != nil {
		return err
	}
	return nil
}
func (s *VPNService) SetAutoStart(enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	return nativeError(C.aesAutoStart(C.int(v)))
}
func (s *VPNService) GetAutoStart() bool { return C.aesAutoStartStatus() == 1 }
func (s *VPNService) verifyProxyTraffic() bool {
	u, _ := url.Parse("socks5://127.0.0.1:10808")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var result struct {
		IP string `json:"ip"`
	}
	return resp.StatusCode == 200 && json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&result) == nil && net.ParseIP(result.IP) != nil
}

func unregisterPlatformHelper() error { return nativeError(C.aesUnregisterHelper()) }
