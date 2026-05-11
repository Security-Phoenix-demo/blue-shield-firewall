//go:build linux
// +build linux

package service

import (
	"fmt"
	"os/exec"
)

type linuxManager struct{}

func New() Manager { return &linuxManager{} }

func (m *linuxManager) Install() error {
	fmt.Println("[service] installing systemd unit (stub — full implementation in B7)")
	return nil
}

func (m *linuxManager) Uninstall() error {
	return exec.Command("systemctl", "disable", "--now", "phoenix-firewall").Run()
}

func (m *linuxManager) Start() error {
	return exec.Command("systemctl", "start", "phoenix-firewall").Run()
}

func (m *linuxManager) Stop() error {
	return exec.Command("systemctl", "stop", "phoenix-firewall").Run()
}

func (m *linuxManager) Status() (string, error) {
	out, err := exec.Command("systemctl", "status", "phoenix-firewall").Output()
	return string(out), err
}
