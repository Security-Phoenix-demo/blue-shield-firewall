// Package telemetry sends periodic heartbeats and verdict events to the backend.
package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/version"
)

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
		"integrity": map[string]string{
			"phoenix_firewall_bin_sha256": fileHash("/usr/local/bin/phoenix-firewall"),
			"ca_pem_sha256":              fileHash("/etc/phoenix-firewall/ca.pem"),
			"agent_toml_sha256":          fileHash("/etc/phoenix-firewall/agent.toml"),
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat returned %d", resp.StatusCode)
	}
	return nil
}

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		// File absent or unreadable — return hash of the path string as a sentinel.
		sum := sha256.Sum256([]byte(path))
		return hex.EncodeToString(sum[:])
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		sum := sha256.Sum256([]byte(path))
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}
