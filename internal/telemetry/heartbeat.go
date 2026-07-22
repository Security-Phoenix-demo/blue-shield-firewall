// Package telemetry sends periodic heartbeats and verdict events to the backend.
package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/integrity"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/version"
)

// HeartbeatError is returned when the heartbeat endpoint responds with a non-2xx
// status. It is distinct from a transport error (backend genuinely unreachable),
// so callers can tell an auth rejection (e.g. a bad/wrong API key -> 401) apart
// from "cannot connect" and log an actionable message instead of a misleading
// "cannot reach backend".
type HeartbeatError struct {
	StatusCode int
	Body       string
}

func (e *HeartbeatError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("heartbeat rejected: HTTP %d: %s", e.StatusCode, e.Body)
	}
	return fmt.Sprintf("heartbeat rejected: HTTP %d", e.StatusCode)
}

// IsAuth reports whether the rejection was an authentication/authorization
// failure (missing, invalid, or wrong-scope API key) rather than another
// server-side error.
func (e *HeartbeatError) IsAuth() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}

// httpClient carries an explicit timeout so a black-holed network can't hang
// the heartbeat goroutine indefinitely.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// HeartbeatSender sends periodic heartbeat payloads to /api/v1/firewall/agent/heartbeat.
type HeartbeatSender struct {
	apiURL    string
	apiKey    string
	tenantID  string
	deviceID  string
	startedAt time.Time
	stopCh    chan struct{}
	// OnResult, if set, is invoked after each send with the send error (nil on
	// success). A *HeartbeatError means the backend responded but rejected the
	// request (e.g. 401 auth failure); any other non-nil error means the backend
	// could not be reached.
	OnResult func(err error)
}

func NewHeartbeatSender(apiURL, apiKey, tenantID, deviceID string) *HeartbeatSender {
	return &HeartbeatSender{
		apiURL:    apiURL,
		apiKey:    apiKey,
		tenantID:  tenantID,
		deviceID:  deviceID,
		startedAt: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

func (h *HeartbeatSender) Start(interval time.Duration) {
	go h.loop(interval)
}

func (h *HeartbeatSender) Stop() { close(h.stopCh) }

func (h *HeartbeatSender) loop(interval time.Duration) {
	// Immediate send so readiness is known at startup, not one interval later.
	h.report(h.send())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.report(h.send())
		}
	}
}

func (h *HeartbeatSender) report(err error) {
	if h.OnResult != nil {
		h.OnResult(err)
	}
}

func (h *HeartbeatSender) send() error {
	binPath, caPath, tomlPath := integrityPaths()
	uptime := int(time.Since(h.startedAt).Seconds())
	if uptime < 0 {
		uptime = 0 // clock skew guard; backend requires uptime_seconds >= 0
	}
	payload := map[string]interface{}{
		"device_id":      h.deviceID,
		"agent_version":  version.Agent,
		"ts":             time.Now().UTC().Format(time.RFC3339),
		"uptime_seconds": uptime,
		"proxy_health":   "running",
		"collector_capabilities": []string{
			"package_manager_shim",
			"developer_software_inventory",
			"package_lockfile_inventory",
			"install_activity_events",
		},
		"endpoint_metadata": map[string]string{
			"hostname":     hostnameBestEffort(),
			"os":           runtime.GOOS,
			"arch":         runtime.GOARCH,
			"team_id_hint": os.Getenv("PHOENIX_TEAM_ID"),
		},
		// Hashes of the actual install artifacts. Paths are resolved for the
		// real (incl. userland ~/.config) layout — the previous hardcoded
		// /usr/local/bin + /etc paths do not exist in a no-root install, which
		// produced empty hashes the backend rejected (min_length=64 -> 422).
		"integrity": map[string]string{
			"phoenix_firewall_bin_sha256": integrity.HashFileOrUnknown(binPath),
			"ca_pem_sha256":               integrity.HashFileOrUnknown(caPath),
			"agent_toml_sha256":           integrity.HashFileOrUnknown(tomlPath),
		},
		"stats": map[string]int{
			"evaluations_5m": 0,
			"blocks_5m":      0,
			"warns_5m":       0,
			"cache_hits_5m":  0,
		},
		// Installs that ran without firewall evaluation since the last heartbeat
		// (proxy unreachable + fail_mode=open). Lets the backend flag hosts where
		// packages — including test samples — executed without being scanned.
		"direct_install_bypass_events": DrainBypassEvents(),
	}
	// Only include tenant_id when we actually have one — the backend resolves the
	// tenant from the API key, and an empty string fails its UUID validation (422).
	if h.tenantID != "" {
		payload["tenant_id"] = h.tenantID
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, h.apiURL+"/api/v1/firewall/agent/heartbeat", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", h.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Include a bounded body snippet so the caller can log the real reason
		// (e.g. {"detail":"Invalid or expired API key"}) rather than a bare code.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &HeartbeatError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(snippet))}
	}
	return nil
}

func hostnameBestEffort() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

// integrityPaths resolves the real locations of the integrity-critical files.
// The binary is the running executable itself; the CA and agent.toml live under
// the userland config dir (~/.config/phoenix-firewall), matching where `enroll`
// and the shims write them. System-wide installs are covered by falling back to
// the legacy /etc path when the userland file is absent.
func integrityPaths() (binPath, caPath, tomlPath string) {
	binPath, _ = os.Executable()

	caPath = "/etc/phoenix-firewall/ca.pem"
	tomlPath = "/etc/phoenix-firewall/agent.toml"
	if home, err := os.UserHomeDir(); err == nil {
		cfgDir := filepath.Join(home, ".config", "phoenix-firewall")
		if p := filepath.Join(cfgDir, "phoenix-ca.crt"); fileExists(p) {
			caPath = p
		}
		if p := filepath.Join(cfgDir, "agent.toml"); fileExists(p) {
			tomlPath = p
		}
	}
	return binPath, caPath, tomlPath
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
