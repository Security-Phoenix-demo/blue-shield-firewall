package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDrainBypassEvents_CountsAndClears(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgDir := filepath.Join(home, ".config", "phoenix-firewall")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath := filepath.Join(cfgDir, "bypass.log")
	content := "2026-07-02T00:00:00Z\tnpm\tunverified_proxy_fail_open\n" +
		"2026-07-02T00:01:00Z\tpip\tunverified_proxy_fail_open\n"
	if err := os.WriteFile(logPath, []byte(content), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	if got := DrainBypassEvents(); got != 2 {
		t.Fatalf("DrainBypassEvents() = %d, want 2", got)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("bypass.log should be consumed (removed) after drain, stat err = %v", err)
	}

	// A second drain with nothing written must be 0, not an error or a repeat count.
	if got := DrainBypassEvents(); got != 0 {
		t.Fatalf("second DrainBypassEvents() = %d, want 0 (nothing new since last drain)", got)
	}
}

func TestDrainBypassEvents_NoFileReturnsZero(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := DrainBypassEvents(); got != 0 {
		t.Fatalf("DrainBypassEvents() with no log file = %d, want 0", got)
	}
}
