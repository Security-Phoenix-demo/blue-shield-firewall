//go:build windows
// +build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

func UserShimDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		home, _ := os.UserHomeDir()
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	return filepath.Join(appData, "PhoenixFirewall", "shims")
}

func InstallPATH() error {
	shimDir := UserShimDir()
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}
	// Windows batch shims instead of bash
	for _, pm := range PackageManagers {
		content := fmt.Sprintf("@echo off\nphoenix-firewall agent-bridge --ecosystem %s --command \"%s %%*\"\n", ecosystemOf(pm), pm)
		path := filepath.Join(shimDir, pm+".cmd")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("write shim %s: %w", pm, err)
		}
	}
	fmt.Printf("[phoenix-firewall] shims installed to %s\n", shimDir)
	fmt.Printf("[phoenix-firewall] add %s to your PATH via System Properties > Environment Variables\n", shimDir)
	return nil
}

func UninstallPATH() error {
	shimDir := UserShimDir()
	for _, pm := range PackageManagers {
		_ = os.Remove(filepath.Join(shimDir, pm+".cmd"))
	}
	return nil
}
