package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type dnsEntry struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

var dnsJournalPath = filepath.Join(stateDir, "dns-recovery.json")
var networkSetup = func(args ...string) ([]byte, error) { return command(5*time.Second, "/usr/sbin/networksetup", args...) }

func readDNS(service string) ([]string, error) {
	out, err := networkSetup("-getdnsservers", service)
	if err != nil {
		return nil, fmt.Errorf("read DNS for %s: %w", service, err)
	}
	text := strings.TrimSpace(string(out))
	if strings.HasPrefix(text, "There aren't any DNS Servers set on ") {
		return nil, nil
	}
	var servers []string
	for _, s := range strings.Fields(text) {
		if s != "" {
			servers = append(servers, s)
		}
	}
	return servers, nil
}
func writeDNSJournal(entries []dnsEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dnsJournalPath), ".dns-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), dnsJournalPath)
}
func installDNS() error {
	out, err := networkSetup("-listallnetworkservices")
	if err != nil {
		return err
	}

	order, err := networkSetup("-listnetworkserviceorder")
	if err != nil {
		return err
	}
	physical := map[string]bool{}
	last := ""
	for _, line := range strings.Split(string(order), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(") && !strings.Contains(line, "Hardware Port:") {
			if i := strings.Index(line, ") "); i > 0 {
				last = line[i+2:]
			}
		}
		if strings.Contains(line, "Device: en") || strings.Contains(line, "Device: bridge") {
			physical[last] = true
		}
	}
	var entries []dnsEntry
	for i, service := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 || strings.HasPrefix(service, "*") || !physical[service] {
			continue
		}
		old, err := readDNS(service)
		if err != nil {
			return err
		}
		entries = append(entries, dnsEntry{service, old})
	}
	if len(entries) == 0 {
		return errors.New("no physical network service found for DNS")
	}

	if err := writeDNSJournal(entries); err != nil {
		return err
	}
	for _, e := range entries {
		if out, err := networkSetup("-setdnsservers", e.Service, "10.99.0.2"); err != nil {
			return fmt.Errorf("set DNS for %s: %s: %w", e.Service, out, err)
		}
	}
	command(3*time.Second, "/usr/bin/dscacheutil", "-flushcache")
	return nil
}
func restoreDNS() error {
	data, err := os.ReadFile(dnsJournalPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries []dnsEntry
	if err = json.Unmarshal(data, &entries); err != nil {
		return err
	}
	var pending []dnsEntry
	var failures []error
	for _, e := range entries {
		current, err := readDNS(e.Service)
		if err != nil {
			pending = append(pending, e)
			failures = append(failures, err)
			continue
		}

		if len(current) != 1 || current[0] != "10.99.0.2" {
			continue
		}
		servers := e.Servers
		if len(servers) == 0 {
			servers = []string{"Empty"}
		}
		args := append([]string{"-setdnsservers", e.Service}, servers...)
		if out, err := networkSetup(args...); err != nil {
			pending = append(pending, e)
			failures = append(failures, fmt.Errorf("restore DNS %s: %s: %w", e.Service, out, err))
		}
	}
	if len(pending) > 0 {
		if err := writeDNSJournal(pending); err != nil {
			failures = append(failures, err)
		}
		return errors.Join(failures...)
	}
	if err := os.Remove(dnsJournalPath); err != nil {
		return err
	}
	command(3*time.Second, "/usr/bin/dscacheutil", "-flushcache")
	return nil
}
