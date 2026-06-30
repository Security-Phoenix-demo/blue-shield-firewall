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

func startEndpointHeartbeat(cfg *config.Config) func() {
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
	sender.Start(interval)
	log.Printf("[phoenix-firewall] endpoint heartbeat enabled for device %s every %s", deviceID, interval)

	var once sync.Once
	return func() {
		once.Do(sender.Stop)
	}
}
