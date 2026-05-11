//go:build windows
// +build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func binaryPath() string {
	if p, err := exec.LookPath("phoenix-firewall.exe"); err == nil {
		return p
	}
	appData := os.Getenv("APPDATA")
	return filepath.Join(appData, "PhoenixFirewall", "phoenix-firewall.exe")
}

type windowsManager struct{}

func New() Manager { return &windowsManager{} }

func (m *windowsManager) Install() error {
	bin := binaryPath()
	// Create scheduled task at user logon (no admin required)
	args := []string{
		"/Create", "/F", "/TN", `PhoenixFirewall\Agent`,
		"/TR", fmt.Sprintf(`"%s" system`, bin),
		"/SC", "ONLOGON",
		"/RL", "LIMITED",
	}
	out, err := exec.Command("schtasks", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create: %w: %s", err, out)
	}
	return nil
}

func (m *windowsManager) Uninstall() error {
	out, err := exec.Command("schtasks", "/Delete", "/F", "/TN", `PhoenixFirewall\Agent`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks delete: %w: %s", err, out)
	}
	return nil
}

func (m *windowsManager) Start() error {
	out, err := exec.Command("schtasks", "/Run", "/TN", `PhoenixFirewall\Agent`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks run: %w: %s", err, out)
	}
	return nil
}

func (m *windowsManager) Stop() error {
	out, err := exec.Command("schtasks", "/End", "/TN", `PhoenixFirewall\Agent`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks end: %w: %s", err, out)
	}
	return nil
}

func (m *windowsManager) Status() (string, error) {
	out, err := exec.Command("schtasks", "/Query", "/TN", `PhoenixFirewall\Agent`, "/FO", "LIST").Output()
	return string(out), err
}
