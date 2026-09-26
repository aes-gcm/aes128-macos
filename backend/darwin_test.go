//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDarwinConfigProtectsDNSAndIPv6(t *testing.T) {
	b, err := generateSingBoxConfig(&AppData{})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]interface{}
	json.Unmarshal(b, &c)
	in := c["inbounds"].([]interface{})[0].(map[string]interface{})
	if in["auto_route"] != true || len(in["address"].([]interface{})) != 2 || in["interface_name"] != nil {
		t.Fatal("incorrect utun routes")
	}
	dns := c["dns"].(map[string]interface{})
	if dns["servers"].([]interface{})[0].(map[string]interface{})["detour"] != "proxy" {
		t.Fatal("DNS bypasses encrypted tunnel")
	}
}
func TestDarwinRejectsUnsupportedProtocolsAndTor(t *testing.T) {
	data := &AppData{UserUUID: "test", Locations: []LocationInfo{{Name: "a", Domain: "example.com", VlessXhttpPort: 443, VlessXTLSPort: 443}}, SelectedLocationName: "a", EnableTor: true}
	if _, err := validateSettings(data); err == nil {
		t.Fatal("XHTTP silently accepted Tor")
	}
	data.Protocol = "vless-xtls"
	if _, err := validateSettings(data); err == nil {
		t.Fatal("missing Tor port accepted")
	}
	data.EnableTor = false
	if _, err := validateSettings(data); err != nil {
		t.Fatal(err)
	}
	data.Protocol = "hysteria2"
	if _, err := validateSettings(data); err == nil {
		t.Fatal("unsupported core accepted")
	}
}
func TestDNSRecoveryRetainsJournalAndUserChanges(t *testing.T) {
	oldPath, oldSetup := dnsJournalPath, networkSetup
	t.Cleanup(func() { dnsJournalPath = oldPath; networkSetup = oldSetup })
	dnsJournalPath = filepath.Join(t.TempDir(), "dns.json")
	if err := writeDNSJournal([]dnsEntry{{"Wi-Fi", nil}, {"USB", []string{"9.9.9.9"}}, {"Manual", nil}}); err != nil {
		t.Fatal(err)
	}
	current := map[string]string{"Wi-Fi": "10.99.0.2", "USB": "10.99.0.2", "Manual": "8.8.8.8"}
	fail := true
	restored := map[string][]string{}
	networkSetup = func(args ...string) ([]byte, error) {
		if args[0] == "-getdnsservers" {
			return []byte(current[args[1]]), nil
		}
		if args[1] == "USB" && fail {
			return nil, errors.New("temporary failure")
		}
		restored[args[1]] = args[2:]
		current[args[1]] = strings.Join(args[2:], "\n")
		return nil, nil
	}
	if err := restoreDNS(); err == nil {
		t.Fatal("restore failure hidden")
	}
	if !reflect.DeepEqual(restored["Wi-Fi"], []string{"Empty"}) {
		t.Fatal("DHCP DNS not restored")
	}
	if _, ok := restored["Manual"]; ok {
		t.Fatal("overwrote user's newer DNS edit")
	}
	if _, err := os.Stat(dnsJournalPath); err != nil {
		t.Fatal("lost recovery journal")
	}
	fail = false
	if err := restoreDNS(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored["USB"], []string{"9.9.9.9"}) {
		t.Fatal("static DNS not restored")
	}
	if _, err := os.Stat(dnsJournalPath); !os.IsNotExist(err) {
		t.Fatal("journal not cleared")
	}
}
