//go:build darwin
// +build darwin

package shim

import (
	"fmt"
	"os"
)

const shimDir = "/usr/local/lib/phoenix-firewall/shims"
const pathsDFile = "/etc/paths.d/0-phoenix-firewall"

// InstallPATH writes the paths.d entry so macOS prepends shimDir to every shell's PATH.
func InstallPATH() error {
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}
	g := &Generator{OutputDir: shimDir}
	if err := g.Generate(); err != nil {
		return err
	}
	return os.WriteFile(pathsDFile, []byte(shimDir+"\n"), 0644)
}

func UninstallPATH() error {
	return os.Remove(pathsDFile)
}
