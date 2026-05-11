//go:build darwin
// +build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const plistLabel = "io.phoenix.security.firewall"

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", plistLabel+".plist")
}

func binaryPath() string {
	if p, err := exec.LookPath("phoenix-firewall"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "phoenix-firewall")
}

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.Binary}}</string>
        <string>system</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/phoenix-firewall.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/phoenix-firewall.err</string>
</dict>
</plist>
`

type darwinManager struct{}

func New() Manager { return &darwinManager{} }

func (m *darwinManager) Install() error {
	home, _ := os.UserHomeDir()
	laPath := launchAgentPath()
	logDir := filepath.Join(home, "Library", "Logs", "PhoenixFirewall")
	if err := os.MkdirAll(filepath.Dir(laPath), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}
	tmpl, _ := template.New("plist").Parse(plistTemplate)
	f, err := os.OpenFile(laPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, struct{ Label, Binary, LogDir string }{
		Label: plistLabel, Binary: binaryPath(), LogDir: logDir,
	})
}

func (m *darwinManager) Uninstall() error {
	_ = exec.Command("launchctl", "unload", launchAgentPath()).Run()
	return os.Remove(launchAgentPath())
}

func (m *darwinManager) Start() error {
	if err := m.Install(); err != nil {
		return fmt.Errorf("install plist: %w", err)
	}
	return exec.Command("launchctl", "load", "-w", launchAgentPath()).Run()
}

func (m *darwinManager) Stop() error {
	return exec.Command("launchctl", "unload", launchAgentPath()).Run()
}

func (m *darwinManager) Status() (string, error) {
	out, err := exec.Command("launchctl", "list", plistLabel).Output()
	return string(out), err
}
