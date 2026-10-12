package logger

import (
	"os"
	"path/filepath"
	"testing"
)

// newTempLogDir creates a temp dir for logger output. zap holds the underlying
// file handle open for the logger's lifetime, so on Windows the dir cannot be
// deleted while the handle is live; we do best-effort cleanup and ignore the
// "file in use" error (the OS releases it when the test process exits).
func newTempLogDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "secauto-logtest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestNewLoggerLevels(t *testing.T) {
	// exercise every level branch without leaving open file handles:
	// stdout branch never opens a file.
	for _, lvl := range []string{"debug", "info", "warn", "error", "trace", "unknown"} {
		l := New(lvl, "stdout")
		if l == nil || l.Logger == nil {
			t.Fatalf("nil logger for level %q", lvl)
		}
	}
}

func TestNewLoggerFileCreated(t *testing.T) {
	dir := newTempLogDir(t)
	target := filepath.Join(dir, "app.log")
	l := New("error", target)
	if l == nil || l.Logger == nil {
		t.Fatal("nil logger")
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("log file not created at %s: %v", target, err)
	}
}

func TestNewLoggerFileInSubdir(t *testing.T) {
	dir := newTempLogDir(t)
	target := filepath.Join(dir, "nested", "logs", "out.log")
	l := New("info", target)
	if l == nil {
		t.Fatal("nil logger")
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("nested log file not created: %v", err)
	}
}
