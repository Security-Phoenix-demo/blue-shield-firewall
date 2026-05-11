//go:build windows
// +build windows

package mdm

import "fmt"

type windowsWriter struct{}

func NewWriter() Writer { return &windowsWriter{} }

func (w *windowsWriter) Write(status Status) error {
	fmt.Printf("[mdm] Windows WMI/registry compliance write (stub — B4 implementation)\n")
	return nil
}
