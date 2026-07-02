// Package telemetry sends periodic heartbeats and verdict events to the backend.
package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/integrity"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/version"
)

// httpClient carries an explicit timeout so a black-holed network can't hang
// the heartbeat goroutine indefinitely.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// HeartbeatSender sends periodic heartbeat payloads to /api/v1/firewall/agent/heartbeat.
type HeartbeatSender struct {
	apiURL   string
	apiKey   string
	tenantID string
	deviceID string
	stopCh   chan struct{}
	// OnResult, if set, is invoked after each send with whether it succeeded.
	OnResult func(ok bool)
}

func NewHeartbeatSender(apiURL, apiKey, tenantID, deviceID string) *HeartbeatSender {
	return &HeartbeatSender{
		apiURL:   apiURL,
		apiKey:   apiKey,
		tenantID: tenantID,
		deviceID: deviceID,
		stopCh:   make(chan struct{}),
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
		h.OnResult(err == nil)
	}
}

func (h *HeartbeatSender) send() error {
	payload := map[string]interface{}{
		"tenant_id":     h.tenantID,
		"device_id":     h.deviceID,
		"agent_version": version.Agent,
		"ts":            time.Now().UTC().Format(time.RFC3339),
		"proxy_health":  "running",
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
		"integrity": map[string]string{
			"phoenix_firewall_bin_sha256": integrity.HashFileBestEffort("/usr/local/bin/phoenix-firewall"),
			"ca_pem_sha256":               integrity.HashFileBestEffort("/etc/phoenix-firewall/ca.pem"),
			"agent_toml_sha256":           integrity.HashFileBestEffort("/etc/phoenix-firewall/agent.toml"),
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
		return fmt.Errorf("heartbeat returned %d", resp.StatusCode)
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
