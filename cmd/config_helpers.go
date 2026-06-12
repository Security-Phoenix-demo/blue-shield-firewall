package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/config"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/policy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// applyHandlerConfig wires runtime features onto the proxy request handler.
// Shared by both entry points (`proxy` and `system`/endpoint mode) so the
// security-relevant settings — strict-mode fail-closed and the policy
// freshness gate — can never silently apply to one path but not the other.
//
// policyGate may be a nil *policy.Syncer (concrete nil), in which case the gate
// is left unset; this avoids the typed-nil-in-interface trap.
func applyHandlerConfig(h *proxy.RequestHandler, cfg *config.Config, reporter *proxy.Reporter, fallbackFeed *proxy.FallbackFeed, policyGate *policy.Syncer) {
	if cfg.StrictMode {
		h.SetStrictMode(true)
	}
	if reporter != nil {
		h.SetReporter(reporter)
	}
	if fallbackFeed != nil {
		h.SetFallbackFeed(fallbackFeed)
	}
	if policyGate != nil {
		h.SetPolicyGate(policyGate)
	}
}

// warnIfAPIKeyFlag warns when the API key was passed as a CLI flag, since flag
// values are visible in the process list and may land in shell history / CI logs.
// Prefer PHOENIX_API_KEY or the enrolled agent.toml.
func warnIfAPIKeyFlag(cmd *cobra.Command) {
	if cmd.Flags().Changed("api-key") {
		fmt.Fprintln(os.Stderr, "[phoenix-firewall] warning: --api-key is visible in the process list; prefer PHOENIX_API_KEY or 'phoenix-firewall enroll'")
	}
}

// agentConfig loads runtime config (CLI flags + PHOENIX_* env via viper) and
// back-fills api_key / api_url from ~/.config/phoenix-firewall/agent.toml when
// they were not supplied. Flags and env always take precedence over the file.
//
// Used by commands that run in a plain user shell (e.g. the shim-invoked
// `bypass verify`), where the only credential source is the enrolled agent.toml.
func agentConfig() *config.Config {
	cfg := config.Load()

	home, err := os.UserHomeDir()
	if err != nil {
		return cfg
	}
	tomlPath := filepath.Join(home, ".config", "phoenix-firewall", "agent.toml")

	lv := viper.New()
	lv.SetConfigFile(tomlPath)
	lv.SetConfigType("toml")
	if err := lv.ReadInConfig(); err != nil {
		return cfg
	}

	if cfg.APIKey == "" {
		cfg.APIKey = lv.GetString("api_key")
	}
	// root.go defaults api-url to the dev URL; prefer the enrolled value.
	if cfg.APIUrl == "" || cfg.APIUrl == "http://localhost:8000" {
		if u := lv.GetString("api_url"); u != "" {
			cfg.APIUrl = u
		}
	}
	return cfg
}
