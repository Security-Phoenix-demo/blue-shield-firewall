// Package proxy — fallback.go provides offline fallback feed support.
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/client"
)

// maxFallbackFeedBytes caps the size of a fallback feed file read into memory.
const maxFallbackFeedBytes = 32 << 20 // 32 MiB

// FallbackEntry represents a single entry in the fallback feed JSON file.
type FallbackEntry struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	Action      string `json:"action"`
}

// FallbackFeed provides offline package checking against a local JSON feed.
type FallbackFeed struct {
	entries map[string]string // "ecosystem:name:version" → action
}

// LoadFallbackFeed reads a JSON file containing an array of FallbackEntry and
// builds a lookup map. Expected format:
//
//	[{"package_name": "evil-pkg", "version": "1.0.0", "ecosystem": "npm", "action": "block"}]
func LoadFallbackFeed(path string) (*FallbackFeed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read fallback feed: %w", err)
	}
	defer f.Close()

	// Bound the read so an oversized file cannot exhaust memory.
	data, err := io.ReadAll(io.LimitReader(f, maxFallbackFeedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read fallback feed: %w", err)
	}
	if int64(len(data)) > maxFallbackFeedBytes {
		return nil, fmt.Errorf("fallback feed too large (exceeded %d bytes)", maxFallbackFeedBytes)
	}

	var entries []FallbackEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		// Do not wrap the parser error: it can echo a slice of file contents.
		return nil, fmt.Errorf("parse fallback feed: invalid JSON")
	}

	feed := &FallbackFeed{
		entries: make(map[string]string, len(entries)),
	}
	for _, e := range entries {
		key := feedKey(e.Ecosystem, e.PackageName, e.Version)
		feed.entries[key] = e.Action
	}

	return feed, nil
}

// Check looks up a package in the fallback feed. Returns a CheckResult and true
// if the package is found, or nil and false if not found (treat as allowed).
func (f *FallbackFeed) Check(ecosystem, name, version string) (*client.CheckResult, bool) {
	// Try exact match first
	key := feedKey(ecosystem, name, version)
	action, ok := f.entries[key]
	if !ok {
		// Try wildcard version match (version = "*")
		wildcardKey := feedKey(ecosystem, name, "*")
		action, ok = f.entries[wildcardKey]
		if !ok {
			return nil, false
		}
	}

	allowed := action != "block"
	verdict := "safe"
	if action == "block" {
		verdict = "malicious"
	} else if action == "warn" {
		verdict = "suspicious"
	}

	return &client.CheckResult{
		Allowed:    allowed,
		Verdict:    verdict,
		Reason:     fmt.Sprintf("fallback feed: action=%s", action),
		Action:     action,
		Confidence: 1.0,
	}, true
}

// Len returns the number of entries in the fallback feed.
func (f *FallbackFeed) Len() int {
	return len(f.entries)
}

// feedKey builds a canonical lookup key.
func feedKey(ecosystem, name, version string) string {
	return strings.ToLower(fmt.Sprintf("%s:%s:%s", ecosystem, name, version))
}
