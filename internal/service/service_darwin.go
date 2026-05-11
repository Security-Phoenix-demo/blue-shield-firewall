//go:build darwin
// +build darwin

package service

import (
	"fmt"
	"os/exec"
)

const launchdPlist = "/Library/LaunchDaemons/io.phoenix.security.firewall.plist"

type darwinManager struct{}

func New() Manager { return &darwinManager{} }

func (m *darwinManager) Install() error {
	fmt.Println("[service] installing launchd daemon (stub — full implementation in B7)")
	return nil
}

func (m *darwinManager) Uninstall() error {
	return exec.Command("launchctl", "unload", launchdPlist).Run()
}

func (m *darwinManager) Start() error {
	return exec.Command("launchctl", "load", "-w", launchdPlist).Run()
}

func (m *darwinManager) Stop() error {
	return exec.Command("launchctl", "unload", launchdPlist).Run()
}

func (m *darwinManager) Status() (string, error) {
	out, err := exec.Command("launchctl", "list", "io.phoenix.security.firewall").Output()
	return string(out), err
}
