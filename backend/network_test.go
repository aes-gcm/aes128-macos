package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGatewayAcrossNetworksAndLanguages(t *testing.T) {
	for _, c := range []struct{ routes, want string }{
		{"Active Routes:\n0.0.0.0 0.0.0.0 10.0.0.1 10.0.0.12 25", "10.0.0.1"},
		{"Активные маршруты:\n0.0.0.0 0.0.0.0 172.16.1.1 172.16.1.4 30\n0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.4 50", "172.16.1.1"},
		{"0.0.0.0 0.0.0.0 203.0.113.1 203.0.113.2 5\n0.0.0.0 0.0.0.0 10.99.0.2 10.99.0.1 1", "203.0.113.1"},
		{"0.0.0.0 0.0.0.0 On-link 10.99.0.1 1", ""},
	} {
		if got := gatewayFromRoutes(c.routes); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
}

func TestSplitTunnelModes(t *testing.T) {
	for _, mode := range []string{"exclude", "tunnel"} {
		route, err := splitTunnelRoute(&AppData{SplitTunnelEnabled: true, SplitTunnelMode: mode, SplitTunnelDomains: "discord.com, example.com, discord.com"})
		if err != nil {
			t.Fatal(err)
		}
		rules := route["rules"].([]interface{})
		last := rules[len(rules)-1].(map[string]interface{})
		wantFinal, wantMatch := "proxy", "direct"
		if mode == "tunnel" {
			wantFinal, wantMatch = "direct", "proxy"
		}
		if route["final"] != wantFinal || last["outbound"] != wantMatch || len(last["domain_suffix"].([]string)) != 2 {
			t.Fatalf("incorrect %s routing: %+v", mode, route)
		}
	}
	if _, err := splitTunnelRoute(&AppData{SplitTunnelEnabled: true, SplitTunnelDomains: `example.com", "outbound":"direct`}); err == nil {
		t.Fatal("accepted invalid domain")
	}
}

func TestCustomLinkEscapesAndValidation(t *testing.T) {
	config, location, err := customXrayConfig("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=xhttp&security=tls&path=%2Fa%3Fb%3D1&host=cdn.example.com&sni=example.com#test")
	if err != nil {
		t.Fatal(err)
	}
	if location.Domain != "example.com" || !strings.Contains(config, `"path": "/a?b=1"`) {
		t.Fatal("URL parameters were not decoded")
	}
	for _, link := range []string{"", "https://example.com", "vless://u@example.com:0", "vless://u@example.com:70000", "vless://u@example.com:443?security=reality", "vless://u@example.com:443?type=unsupported"} {
		if _, _, err := customXrayConfig(link); err == nil {
			t.Errorf("accepted invalid link %q", link)
		}
	}
}

func TestShippedCoreConfigurationCompatibility(t *testing.T) {
	coreDir := os.Getenv("AES128_CORE_DIR")
	if coreDir == "" {
		t.Skip("set AES128_CORE_DIR to validate configurations with shipped executables")
	}
	t.Setenv("ProgramData", t.TempDir())
	data := &AppData{UserUUID: "11111111-1111-4111-8111-111111111111", Protocol: "vless-xhttp"}
	loc := &LocationInfo{Domain: "example.com", VlessXhttpPort: 443, VlessXTLSPort: 443}
	xhttp, err := generateXrayConfig(data, loc)
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string]string{"xhttp": xhttp, "xtls": generateXrayXTLSConfig(data, loc)}
	for _, transport := range []string{"tcp", "xhttp", "ws", "grpc"} {
		config, _, err := customXrayConfig("vless://" + data.UserUUID + "@example.com:443?security=tls&type=" + transport + "&path=%2Fvpn&serviceName=vpn")
		if err != nil {
			t.Fatal(err)
		}
		configs["custom-"+transport] = config
	}
	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			os.WriteFile(path, []byte(config), 0600)
			output, err := exec.Command(filepath.Join(coreDir, coreBinaryName("xray")), "run", "-test", "-c", path).CombinedOutput()
			if err != nil {
				t.Fatalf("Xray rejected config: %v\n%s", err, output)
			}
		})
	}
	for _, mode := range []string{"off", "exclude", "tunnel"} {
		t.Run("singbox-"+mode, func(t *testing.T) {
			data.SplitTunnelEnabled = mode != "off"
			data.SplitTunnelMode = mode
			data.SplitTunnelDomains = "discord.com,example.com"
			config, err := generateSingBoxConfig(data)
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(config) {
				t.Fatal("invalid JSON")
			}
			path := filepath.Join(t.TempDir(), "config.json")
			os.WriteFile(path, config, 0600)
			output, err := exec.Command(filepath.Join(coreDir, coreBinaryName("sing-box")), "check", "-c", path).CombinedOutput()
			if err != nil {
				t.Fatalf("sing-box rejected config: %v\n%s", err, output)
			}
		})
	}
}

func coreBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		if name == "sing-box" {
			return "core.exe"
		}
		return name + ".exe"
	}
	return name
}
