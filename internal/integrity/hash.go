// Package integrity computes and verifies SHA-256 hashes of critical agent files.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// FileHashes holds the SHA-256 of the three integrity-critical files.
type FileHashes struct {
	BinarySHA256    string
	CAPEMSHA256     string
	AgentTOMLSHA256 string
}

// Compute calculates current SHA-256 hashes for all three files.
func Compute(binaryPath, caPEMPath, agentTOMLPath string) (*FileHashes, error) {
	b, err := hashFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("hash binary: %w", err)
	}
	c, err := hashFile(caPEMPath)
	if err != nil {
		return nil, fmt.Errorf("hash CA PEM: %w", err)
	}
	a, err := hashFile(agentTOMLPath)
	if err != nil {
		return nil, fmt.Errorf("hash agent.toml: %w", err)
	}
	return &FileHashes{BinarySHA256: b, CAPEMSHA256: c, AgentTOMLSHA256: a}, nil
}

// HashFileBestEffort returns the hex SHA-256 of the file at path, or "" if the
// file cannot be read. Use when a missing/unreadable file should not be fatal
// (e.g. integrity fields in a telemetry heartbeat).
func HashFileBestEffort(path string) string {
	h, err := hashFile(path)
	if err != nil {
		return ""
	}
	return h
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
