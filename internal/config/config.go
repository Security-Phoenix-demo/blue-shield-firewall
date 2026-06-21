// Package config provides configuration loading for the Phoenix firewall proxy.
// Configuration is resolved from environment variables (PHOENIX_ prefix) and CLI flags.
package config

import "github.com/spf13/viper"

// Config holds all runtime configuration for the firewall proxy.
type Config struct {
	// APIUrl is the base URL of the Phoenix firewall API.
	APIUrl string
	// APIKey is the authentication key for the firewall API.
	APIKey string
	// DeviceID is the endpoint UUID assigned by Phoenix.
	DeviceID string
	// TeamID is an optional collector-side hint for display/reconciliation only.
	TeamID string
	// Port is the local port the proxy listens on.
	Port int
	// Verbose enables debug-level logging.
	Verbose bool
	// LogFormat controls log output format ("json" or "text").
	LogFormat string
	// StrictMode blocks packages on any API error (fail-closed).
	StrictMode bool
	// CIMode enables CI-friendly output (exit codes, structured reports).
	CIMode bool
	// FallbackFeed is the path to a local JSON feed used when the API is unreachable.
	FallbackFeed string
	// ReportPath is the file path where scan reports are written.
	ReportPath string
	// ExtraRegistries is a list of additional registry domains to intercept.
	// Format: "ecosystem:hostname" (e.g. "npm:gitlab.example.com").
	ExtraRegistries []string
	// GitLabHosts is a list of GitLab instance hostnames whose package registries
	// should be intercepted (e.g. "gitlab.example.com"). gitlab.com is always included.
	GitLabHosts []string
	// EnforcePolicyFreshness, when true, blocks installs (fail-closed) once the
	// downloaded firewall policy is staler than the hard threshold (R-FUNC-073).
	// Default false: enabling it requires a reachable policy endpoint.
	EnforcePolicyFreshness bool
	// FailMode controls behavior when the Phoenix backend cannot be reached:
	// "open" allows installs (default), "closed" blocks them. Sourced from
	// agent.toml [fail_mode] mode or env PHOENIX_FAIL_MODE.
	FailMode string
}

// Load reads configuration from viper (flags + env vars) and returns a Config.
func Load() *Config {
	return &Config{
		APIUrl:          viper.GetString("api_url"),
		APIKey:          viper.GetString("api_key"),
		DeviceID:        viper.GetString("device_id"),
		TeamID:          viper.GetString("team_id"),
		Port:            viper.GetInt("port"),
		Verbose:         viper.GetBool("verbose"),
		LogFormat:       viper.GetString("log_format"),
		StrictMode:      viper.GetBool("strict_mode"),
		CIMode:          viper.GetBool("ci_mode"),
		FallbackFeed:    viper.GetString("fallback_feed"),
		ReportPath:      viper.GetString("report_path"),
		ExtraRegistries: viper.GetStringSlice("extra_registries"),
		GitLabHosts:     viper.GetStringSlice("gitlab_hosts"),

		EnforcePolicyFreshness: viper.GetBool("enforce_policy_freshness"),
		FailMode:               failModeOrDefault(viper.GetString("fail_mode.mode")),
	}
}

// failModeOrDefault normalizes an empty/unknown fail mode to the shipped default "open".
func failModeOrDefault(mode string) string {
	if mode == "closed" {
		return "closed"
	}
	return "open"
}
