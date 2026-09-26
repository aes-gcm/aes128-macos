package main

import (
	"encoding/json"
	"fmt"
)

const xraySocksPort = 10808

type LocationInfo struct {
	Name               string `json:"name"`
	Domain             string `json:"domain"`
	IPAddress          string `json:"ip_address"`
	VlessXhttpPort     int    `json:"vless_xhttp_port"`
	VmessPort          int    `json:"vmess_port"`
	TrojanPort         int    `json:"trojan_port"`
	VlessXTLSPort      int    `json:"vless_xtls_port"`
	RealityPK          string `json:"reality_pk"`
	VlessRealityPort   int    `json:"vless_reality_port"`
	VlessXTLSTorPort   int    `json:"vless_xtls_tor_port"`
	HysteriaPort       int    `json:"hysteria_port"`
	HysteriaSalamander string `json:"hysteria_salamander"`
}

type AppData struct {
	UserData             interface{}    `json:"userData"`
	Locations            []LocationInfo `json:"locations"`
	UserUUID             string         `json:"user_uuid"`
	SessionName          string         `json:"sessionName"`
	LatestAppVersion     string         `json:"latestAppVersion"`
	Protocol             string         `json:"protocol"`
	IsMini               bool           `json:"isMini"`
	EnableTor            bool           `json:"enableTor"`
	UseCustomLink        bool           `json:"useCustomLink"`
	CustomV2rayLink      string         `json:"customV2rayLink"`
	SelectedLocationName string         `json:"selectedLocationName"`
	SplitTunnelEnabled   bool           `json:"splitTunnelEnabled"`
	SplitTunnelDomains   string         `json:"splitTunnelDomains"`
	SplitTunnelDiscord   bool           `json:"splitTunnelDiscord"`
	SplitTunnelSteam     bool           `json:"splitTunnelSteam"`
	SplitTunnelCustom    string         `json:"splitTunnelCustom"`
	SplitTunnelMode      string         `json:"splitTunnelMode"`
	AutoStart            bool           `json:"autoStart"`
	AutoConnect          bool           `json:"autoConnect"`
	KillSwitch           bool           `json:"killSwitch"`
}

func findLocation(locations []LocationInfo, name string) *LocationInfo {
	for i := range locations {
		if locations[i].Name == name {
			return &locations[i]
		}
	}
	if len(locations) > 0 && (name == "" || name == "Fastest server") {
		return &locations[0]
	}
	return nil
}

func generateXrayConfig(appData *AppData, loc *LocationInfo) (string, error) {
	port := loc.VlessXhttpPort
	if port == 0 {
		port = 443
	}
	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
			"access":   "none",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag": "socks-in", "port": xraySocksPort,
				"listen": "127.0.0.1", "protocol": "socks",
				"settings": map[string]interface{}{"udp": true},
			},
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag": "proxy", "protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": loc.Domain, "port": port,
							"users": []interface{}{
								map[string]interface{}{"id": appData.UserUUID, "encryption": "none"},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": "xhttp", "security": "tls",
					"tlsSettings": map[string]interface{}{
						"serverName": loc.Domain, "fingerprint": "chrome",
						"alpn": []string{"h2", "http/1.1"},
					},
					"xhttpSettings": map[string]interface{}{
						"path": "/sync/v2/push", "host": loc.Domain, "mode": "auto",
					},
				},
			},
			map[string]interface{}{"tag": "direct", "protocol": "freedom"},
		},
		"routing": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"type": "field", "ip": []string{
					"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
				}, "outboundTag": "direct"},
			},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	return string(data), err
}

func generateXrayXTLSConfig(appData *AppData, loc *LocationInfo) string {
	port := loc.VlessXTLSPort
	if appData.EnableTor && loc.VlessXTLSTorPort > 0 {
		port = loc.VlessXTLSTorPort
	}
	if port == 0 {
		port = 443
	}
	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
			"access":   "none",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag": "socks-in", "port": xraySocksPort,
				"listen": "127.0.0.1", "protocol": "socks",
				"settings": map[string]interface{}{"udp": true},
			},
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag": "proxy", "protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": loc.Domain, "port": port,
							"users": []interface{}{
								map[string]interface{}{
									"id": appData.UserUUID, "encryption": "none",
									"flow": "xtls-rprx-vision",
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": "tcp", "security": "tls",
					"tlsSettings": map[string]interface{}{
						"serverName": loc.Domain, "fingerprint": "chrome",
						"alpn": []string{"h2", "http/1.1"},
					},
				},
			},
			map[string]interface{}{"tag": "direct", "protocol": "freedom"},
		},
		"routing": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"type": "field", "ip": []string{
					"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
				}, "outboundTag": "direct"},
			},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return string(data)
}

func generateHysteria2Config(appData *AppData, loc *LocationInfo) (string, error) {
	port := loc.HysteriaPort
	if port == 0 {
		return "", fmt.Errorf("hysteria port not configured for %s", loc.Name)
	}

	cfg := map[string]interface{}{
		"server": fmt.Sprintf("%s:%d", loc.Domain, port),
		"auth":   appData.UserUUID,
		"tls": map[string]interface{}{
			"sni":      loc.Domain,
			"insecure": false,
		},
		"socks5": map[string]interface{}{
			"listen": fmt.Sprintf("127.0.0.1:%d", xraySocksPort),
		},
	}

	if loc.HysteriaSalamander != "" {
		cfg["obfs"] = map[string]interface{}{
			"type":       "salamander",
			"salamander": map[string]interface{}{"password": loc.HysteriaSalamander},
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	return string(data), err
}
