package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var xraySHA256, singBoxSHA256 string

func secureDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || stat.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("unsafe privileged directory: %s", path)
	}
	return nil
}
func installTrustedCores() error {
	dest := filepath.Join(stateDir, "cores")
	if err := secureDirectory(dest, 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	for name, expected := range map[string]string{"xray": xraySHA256, "sing-box": singBoxSHA256} {
		if len(expected) != 64 {
			return errors.New("helper was built without pinned core hashes; use build-macos.sh")
		}

		src, err := os.Open(filepath.Join(filepath.Dir(exe), name))
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(src, 64*1024*1024+1))
		src.Close()
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if len(data) > 64*1024*1024 || hex.EncodeToString(sum[:]) != expected {
			return fmt.Errorf("%s integrity check failed", name)
		}
		tmp, err := os.CreateTemp(dest, ".core-*")
		if err != nil {
			return err
		}
		path := tmp.Name()
		if _, err = tmp.Write(data); err == nil {
			err = tmp.Chmod(0700)
		}
		if err == nil {
			err = tmp.Sync()
		}
		closeErr := tmp.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(path, filepath.Join(dest, name))
		}
		os.Remove(path)
		if err != nil {
			return err
		}
	}
	return nil
}
