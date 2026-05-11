//go:build darwin
// +build darwin

package mdm

import "fmt"

type darwinWriter struct{}

func NewWriter() Writer { return &darwinWriter{} }

// Write outputs compliance data as JAMF extension attribute XML to stdout.
// JAMF script policy reads this and writes to inventory.
func (w *darwinWriter) Write(status Status) error {
	fmt.Printf("<result>%v|%s|%v</result>\n", status.IntegrityOK, status.AgentVersion, status.ProxyRunning)
	return nil
}
