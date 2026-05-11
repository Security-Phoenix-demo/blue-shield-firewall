//go:build windows
// +build windows

package service

import "fmt"

type windowsManager struct{}

func New() Manager { return &windowsManager{} }

func (m *windowsManager) Install() error {
	fmt.Println("[service] installing Windows SCM service (stub — full implementation in B7)")
	return nil
}

func (m *windowsManager) Uninstall() error {
	fmt.Println("[service] uninstall SCM service (stub)")
	return nil
}

func (m *windowsManager) Start() error {
	fmt.Println("[service] start SCM service (stub)")
	return nil
}

func (m *windowsManager) Stop() error {
	fmt.Println("[service] stop SCM service (stub)")
	return nil
}

func (m *windowsManager) Status() (string, error) {
	return "stub — not yet implemented", nil
}
