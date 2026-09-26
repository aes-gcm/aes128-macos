package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func gatewayFromRoutes(output string) string {
	best, metric := "", int(^uint(0)>>1)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		ip := net.ParseIP(fields[2])
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || fields[2] == "10.99.0.2" {
			continue
		}
		n, err := strconv.Atoi(fields[4])
		if err == nil && n < metric {
			best, metric = fields[2], n
		}
	}
	return best
}

func splitTunnelRoute(data *AppData) (map[string]interface{}, error) {
	rules := []interface{}{
		map[string]interface{}{"port": 53, "action": "hijack-dns"},
		map[string]interface{}{"action": "sniff"},
		map[string]interface{}{"ip_is_private": true, "outbound": "direct"},
	}
	final := "proxy"
	if data.SplitTunnelEnabled {
		mode := data.SplitTunnelMode
		if mode == "" {
			mode = "exclude"
		}
		if mode != "exclude" && mode != "tunnel" {
			return nil, fmt.Errorf("invalid split tunneling mode")
		}
		var domains []string
		seen := map[string]bool{}
		for _, raw := range strings.Split(data.SplitTunnelDomains, ",") {
			d := strings.ToLower(strings.TrimSpace(raw))
			if d == "" {
				continue
			}
			if !validDomainSuffix(d) {
				return nil, fmt.Errorf("invalid split tunnel domain: %s", d)
			}
			if !seen[d] {
				domains = append(domains, d)
				seen[d] = true
			}
		}
		outbound := "direct"
		if mode == "tunnel" {
			final, outbound = "direct", "proxy"
		}
		if len(domains) > 0 {
			rules = append(rules, map[string]interface{}{"domain_suffix": domains, "outbound": outbound})
		}
	}
	return map[string]interface{}{"auto_detect_interface": true, "rules": rules, "final": final}, nil
}

func validDomainSuffix(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func customXrayConfig(link string) (string, *LocationInfo, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "vless" || u.User == nil || u.User.Username() == "" || u.Hostname() == "" {
		return "", nil, fmt.Errorf("enter a valid vless:// link")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", nil, fmt.Errorf("custom server port must be between 1 and 65535")
	}
	q := u.Query()
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "raw" && network != "xhttp" && network != "ws" && network != "grpc" {
		return "", nil, fmt.Errorf("unsupported custom transport: %s", network)
	}
	security := q.Get("security")
	if security == "" {
		security = "none"
	}
	serverName := q.Get("sni")
	if serverName == "" {
		serverName = u.Hostname()
	}
	fingerprint := q.Get("fp")
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	stream := map[string]interface{}{"network": network, "security": security}
	switch security {
	case "tls":
		stream["tlsSettings"] = map[string]interface{}{"serverName": serverName, "fingerprint": fingerprint}
	case "reality":
		if q.Get("pbk") == "" {
			return "", nil, fmt.Errorf("Reality link is missing its public key")
		}
		stream["realitySettings"] = map[string]interface{}{"serverName": serverName, "fingerprint": fingerprint, "publicKey": q.Get("pbk"), "shortId": q.Get("sid")}
	case "none":
	default:
		return "", nil, fmt.Errorf("unsupported custom security: %s", security)
	}
	switch network {
	case "xhttp":
		mode := q.Get("mode")
		if mode == "" {
			mode = "auto"
		}
		stream["xhttpSettings"] = map[string]interface{}{"path": q.Get("path"), "host": q.Get("host"), "mode": mode}
	case "ws":
		stream["wsSettings"] = map[string]interface{}{"path": q.Get("path"), "headers": map[string]string{"Host": q.Get("host")}}
	case "grpc":
		stream["grpcSettings"] = map[string]interface{}{"serviceName": q.Get("serviceName")}
	}
	user := map[string]interface{}{"id": u.User.Username(), "encryption": "none"}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	config := map[string]interface{}{
		"log":       map[string]interface{}{"loglevel": "warning"},
		"inbounds":  []interface{}{map[string]interface{}{"tag": "socks-in", "listen": "127.0.0.1", "port": xraySocksPort, "protocol": "socks", "settings": map[string]interface{}{"udp": true}}},
		"outbounds": []interface{}{map[string]interface{}{"tag": "proxy", "protocol": "vless", "settings": map[string]interface{}{"vnext": []interface{}{map[string]interface{}{"address": u.Hostname(), "port": port, "users": []interface{}{user}}}}, "streamSettings": stream}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	return string(data), &LocationInfo{Name: "Custom server", Domain: u.Hostname()}, err
}

func generateSingBoxConfig(appData *AppData) ([]byte, error) {
	routeConfig, err := splitTunnelRoute(appData)
	if err != nil {
		return nil, err
	}
	sbCfg := map[string]interface{}{
		"log": map[string]interface{}{"level": "warn", "timestamp": true},
		"dns": map[string]interface{}{
			"reverse_mapping": true,
			"servers": []interface{}{
				map[string]interface{}{"tag": "dns-direct", "address": "185.222.222.222", "detour": "direct"},
			}, "final": "dns-direct",
		},
		"inbounds": []interface{}{map[string]interface{}{
			"type": "tun", "tag": "tun-in", "interface_name": "aes128",
			"stack": "gvisor", "mtu": 1500,
			"address": []string{"10.99.0.1/30"}, "auto_route": false,
		}},
		"outbounds": []interface{}{
			map[string]interface{}{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": xraySocksPort},
			map[string]interface{}{"type": "direct", "tag": "direct"},
		},
		"route": routeConfig,
	}

	platformSingBoxConfig(sbCfg)
	return json.MarshalIndent(sbCfg, "", "  ")
}
