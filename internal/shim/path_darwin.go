//go:build darwin
// +build darwin

package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

// UserShimDir returns the user-local shim directory (~/.local/bin).
func UserShimDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin")
}

// InstallPATH installs shims to ~/.local/bin and adds it to ~/.zprofile and ~/.profile.
// failMode is "open" or "closed" and is baked into each shim at generation time.
// No root required.
func InstallPATH(failMode string) error {
	shimDir := UserShimDir()
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}
	g := &Generator{OutputDir: shimDir, FailMode: failMode}
	if err := g.Generate(); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	line := fmt.Sprintf("\n# Phoenix Security Blue Shield - Firewall\nexport PATH=\"%s:$PATH\"\n", shimDir)
	for _, rc := range []string{".zprofile", ".profile", ".bash_profile"} {
		rcPath := filepath.Join(home, rc)
		if _, err := os.Stat(rcPath); os.IsNotExist(err) {
			continue
		}
		content, _ := os.ReadFile(rcPath)
		if !containsShimEntry(string(content)) {
			f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				continue
			}
			_, _ = f.WriteString(line)
			f.Close()
		}
	}
	fmt.Printf("[phoenix-firewall] shims installed to %s\n", shimDir)
	fmt.Println("[phoenix-firewall] restart your shell or run: export PATH=\"" + shimDir + ":$PATH\"")
	return nil
}

func UninstallPATH() error {
	shimDir := UserShimDir()
	g := &Generator{OutputDir: shimDir}
	for _, pm := range PackageManagers {
		_ = os.Remove(filepath.Join(shimDir, pm))
	}
	_ = g
	fmt.Printf("[phoenix-firewall] shims removed from %s\n", shimDir)
	return nil
}

func containsShimEntry(content string) bool {
	return len(content) > 0 && (containsStr(content, "phoenix-firewall") || containsStr(content, ".local/bin"))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
