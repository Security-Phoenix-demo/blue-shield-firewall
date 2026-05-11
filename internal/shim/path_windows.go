//go:build windows
// +build windows

package shim

import "fmt"

const shimDir = `C:\ProgramFiles\PhoenixFirewall\shims`

func InstallPATH() error {
	fmt.Printf("[shim] Windows PATH injection via registry (stub — full implementation in B2)\n")
	// TODO(B2): use golang.org/x/sys/windows/registry to prepend shimDir to HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path
	return nil
}

func UninstallPATH() error {
	fmt.Printf("[shim] Windows PATH cleanup (stub)\n")
	return nil
}
