//go:build linux
// +build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

func systemdUnitPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", "phoenix-firewall.service")
}

func binaryPath() string {
	if p, err := exec.LookPath("phoenix-firewall"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "phoenix-firewall")
}

const unitTemplate = `[Unit]
Description=Phoenix Security Blue Shield - Firewall (userland)
After=network.target

[Service]
ExecStart={{.Binary}} system
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
`

type linuxManager struct{}

func New() Manager { return &linuxManager{} }

func (m *linuxManager) Install() error {
	unitPath := systemdUnitPath()
	if err := os.MkdirAll(filepath.Dir(unitPath), 0755); err != nil {
		return err
	}
	tmpl, _ := template.New("unit").Parse(unitTemplate)
	f, err := os.OpenFile(unitPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, struct{ Binary string }{Binary: binaryPath()})
}

func (m *linuxManager) Uninstall() error {
	_ = exec.Command("systemctl", "--user", "disable", "--now", "phoenix-firewall").Run()
	return os.Remove(systemdUnitPath())
}

func (m *linuxManager) Start() error {
	if err := m.Install(); err != nil {
		return fmt.Errorf("install unit: %w", err)
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return exec.Command("systemctl", "--user", "enable", "--now", "phoenix-firewall").Run()
}

func (m *linuxManager) Stop() error {
	return exec.Command("systemctl", "--user", "stop", "phoenix-firewall").Run()
}

func (m *linuxManager) Status() (string, error) {
	out, err := exec.Command("systemctl", "--user", "status", "phoenix-firewall").Output()
	return string(out), err
}
