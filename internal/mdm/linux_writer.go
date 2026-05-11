//go:build linux
// +build linux

package mdm

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const compliancePath = "/var/lib/phoenix-firewall/compliance.json"

type linuxWriter struct{}

func NewWriter() Writer { return &linuxWriter{} }

func (w *linuxWriter) Write(status Status) error {
	if err := os.MkdirAll(filepath.Dir(compliancePath), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(compliancePath, b, 0600)
}
