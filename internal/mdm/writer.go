// Package mdm writes compliance attributes to MDM platforms.
package mdm

import "time"

// Status represents the current compliance state written to MDM.
type Status struct {
	AgentVersion  string
	PolicyVersion string
	LastHeartbeat time.Time
	IntegrityOK   bool
	ProxyRunning  bool
}

// Writer writes compliance status to the platform-specific MDM backend.
type Writer interface {
	Write(status Status) error
}
