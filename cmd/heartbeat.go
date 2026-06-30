package cmd

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/config"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/endpoint"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/telemetry"
)

func startEndpointHeartbeat(cfg *config.Config) func() {
	if cfg.APIKey == "" {
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
			interval = time.Duration(seconds) * time.Second
		}
	}

	tenantID := cfg.TenantID
	if tenantID == "" {
		tenantID = os.Getenv("PHOENIX_TENANT_ID") // legacy fallback
	}
	sender := telemetry.NewHeartbeatSender(cfg.APIUrl, cfg.APIKey, tenantID, deviceID)
	sender.Start(interval)
	log.Printf("[phoenix-firewall] endpoint heartbeat enabled for device %s every %s", deviceID, interval)
	return sender.Stop
}
