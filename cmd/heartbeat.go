package cmd

import (
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/config"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/endpoint"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/telemetry"
)

// startEndpointHeartbeat starts a single periodic heartbeat sender for the given
// config and returns a stop function. If onResult is non-nil it is invoked after
// each send with the send error (nil on success), letting callers drive
// backend-reachability readiness and warnings. Returns a no-op stop when there
// is no API key or resolvable device ID.
func startEndpointHeartbeat(cfg *config.Config, onResult func(error)) func() {
	if cfg == nil || cfg.APIKey == "" {
		return func() {}
	}

	deviceID := cfg.DeviceID
	if deviceID == "" {
		deviceID = endpoint.Collect().DeviceID
	}
	if deviceID == "" {
		return func() {}
	}

	interval := 300 * time.Second
	if raw := os.Getenv("PHOENIX_HEARTBEAT_INTERVAL_SECONDS"); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			if seconds < 10 {
				seconds = 10
			}
			interval = time.Duration(seconds) * time.Second
		}
	}

	sender := telemetry.NewHeartbeatSender(cfg.APIUrl, cfg.APIKey, cfg.TenantID, deviceID)
	sender.OnResult = onResult
	sender.Start(interval)
	log.Printf("[phoenix-firewall] endpoint heartbeat enabled for device %s every %s", deviceID, interval)

	var once sync.Once
	return func() {
		once.Do(sender.Stop)
	}
}
