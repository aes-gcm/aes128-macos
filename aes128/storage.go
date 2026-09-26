package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func (s *VPNService) storageKey() ([]byte, error) {
	s.keyLock.Lock()
	defer s.keyLock.Unlock()
	if len(s.encryptionKey) == 32 {
		return s.encryptionKey, nil
	}
	key, err := getEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("session storage is unavailable; repair the AES128 VPN installation: %w", err)
	}
	s.encryptionKey = key
	return key, nil
}

func atomicWriteFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".aes128-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (s *VPNService) writeEncryptedFile(name string, data []byte) error {
	key, err := s.storageKey()
	if err != nil {
		return err
	}
	path, err := getConfigPath(name)
	if err != nil {
		return err
	}
	encrypted, err := encrypt(data, key)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, encrypted)
}

func (s *VPNService) checkSessionStorage() error {
	if _, err := s.storageKey(); err != nil {
		return err
	}
	path, err := getConfigPath(tokenFileName)
	if err != nil {
		return err
	}
	probe, err := os.CreateTemp(filepath.Dir(path), ".session-check-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Remove(name)
}
