// Package telemetry sends periodic heartbeats and verdict events to the backend.
package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/integrity"
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
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			_ = h.send()
		}
	}
}

func (h *HeartbeatSender) send() error {
	payload := map[string]interface{}{
		"tenant_id":     h.tenantID,
		"device_id":     h.deviceID,
		"agent_version": "0.1.0",
		"ts":            time.Now().UTC().Format(time.RFC3339),
		"proxy_health":  "running",
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
	return nil
}
