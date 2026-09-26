package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type rotatingLog struct {
	mu    sync.Mutex
	path  string
	limit int64
}

func (w *rotatingLog) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := rotateLog(w.path, w.limit); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Write(data)
}

var _ io.Writer = (*rotatingLog)(nil)

func rotateLog(path string, limit int64) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() < limit {
		return nil
	}
	backup := path + ".1"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate %s: %w", filepath.Base(path), err)
	}
	return os.Rename(path, backup)
}
