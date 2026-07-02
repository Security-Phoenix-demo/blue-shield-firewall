package telemetry

import (
	"os"
	"path/filepath"
	"strings"
)

// BypassLogPath returns the local path shims append to whenever a package
// manager runs without firewall evaluation (proxy unreachable, fail_mode=open).
// Empty if the home directory can't be resolved.
func BypassLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "phoenix-firewall", "bypass.log")
}

// DrainBypassEvents reads and clears the local bypass log, returning the
// count of unscanned-install events recorded since the last drain. Used by
// the heartbeat sender to surface direct-host (proxy-bypassing) installs to
// the backend, since the shim itself has no network access of its own.
//
// Renames the file before reading so a shim appending concurrently always
// lands in a fresh file at the original path rather than racing this read.
func DrainBypassEvents() int {
	path := BypassLogPath()
	if path == "" {
		return 0
	}
	tmp := path + ".draining"
	if err := os.Rename(path, tmp); err != nil {
		return 0
	}
	defer os.Remove(tmp)

	data, err := os.ReadFile(tmp)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			count++
		}
	}
	return count
}
