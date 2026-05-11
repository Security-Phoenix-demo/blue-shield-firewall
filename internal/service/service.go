// Package service provides OS-native service installation and management.
package service

// Manager installs, uninstalls, starts, stops, and queries the phoenix-firewall
// as a privileged OS service (launchd on macOS, systemd on Linux, SCM on Windows).
type Manager interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Status() (string, error)
}
