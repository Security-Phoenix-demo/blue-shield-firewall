//go:build linux
// +build linux

package shim

import (
	"fmt"
	"os"
)

const shimDir = "/usr/local/lib/phoenix-firewall/shims"
const profileDFile = "/etc/profile.d/phoenix-firewall.sh"

func InstallPATH() error {
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}
	g := &Generator{OutputDir: shimDir}
	if err := g.Generate(); err != nil {
		return err
	}
	script := fmt.Sprintf(`# Phoenix Supply Chain Firewall — added by phoenix-firewall init
export PATH="%s:$PATH"
`, shimDir)
	return os.WriteFile(profileDFile, []byte(script), 0644)
}

func UninstallPATH() error {
	return os.Remove(profileDFile)
}
