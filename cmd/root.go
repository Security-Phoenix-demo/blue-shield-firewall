// Package cmd implements the CLI commands for the Phoenix Security Supply Chain Firewall.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "phoenix-firewall",
	Short: "Phoenix Security Supply Chain Firewall",
	Long: `A MITM proxy that intercepts package manager registry requests
(npm, pip, cargo, gem, maven), checks packages against the Phoenix
Security firewall API, and blocks or warns on malicious packages.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().String("api-url", "http://localhost:8000", "Phoenix firewall API base URL")
	rootCmd.PersistentFlags().String("api-key", "", "Phoenix firewall API key")
	rootCmd.PersistentFlags().String("device-id", "", "Endpoint device UUID assigned by Phoenix")
	rootCmd.PersistentFlags().String("team-id", "", "Optional team hint stored as collector metadata only")
	rootCmd.PersistentFlags().Int("port", 8080, "Proxy listen port")
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose logging")
	rootCmd.PersistentFlags().String("log-format", "text", "Log format (json|text)")
	rootCmd.PersistentFlags().Bool("ci", false, "CI mode: non-interactive, exit code 1 if any package blocked")
	rootCmd.PersistentFlags().Bool("strict", false, "Strict mode: treat warn actions as block")
	rootCmd.PersistentFlags().String("fallback-feed", "", "Path to local JSON feed file for offline mode")
	rootCmd.PersistentFlags().String("report-path", "", "Path to write JSON scan report")
	rootCmd.PersistentFlags().StringSlice("gitlab-hosts", nil, "GitLab instance hostnames to intercept (e.g. gitlab.example.com)")
	rootCmd.PersistentFlags().StringSlice("extra-registries", nil, "Additional registries as ecosystem:host (e.g. npm:packages.example.com)")
	rootCmd.PersistentFlags().Bool("enforce-policy-freshness", false, "Fail closed (block) when the firewall policy is staler than 24h (requires a reachable policy endpoint)")

	_ = viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api-url"))
	_ = viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))
	_ = viper.BindPFlag("device_id", rootCmd.PersistentFlags().Lookup("device-id"))
	_ = viper.BindPFlag("team_id", rootCmd.PersistentFlags().Lookup("team-id"))
	_ = viper.BindPFlag("port", rootCmd.PersistentFlags().Lookup("port"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("ci_mode", rootCmd.PersistentFlags().Lookup("ci"))
	_ = viper.BindPFlag("strict_mode", rootCmd.PersistentFlags().Lookup("strict"))
	_ = viper.BindPFlag("fallback_feed", rootCmd.PersistentFlags().Lookup("fallback-feed"))
	_ = viper.BindPFlag("report_path", rootCmd.PersistentFlags().Lookup("report-path"))
	_ = viper.BindPFlag("gitlab_hosts", rootCmd.PersistentFlags().Lookup("gitlab-hosts"))
	_ = viper.BindPFlag("extra_registries", rootCmd.PersistentFlags().Lookup("extra-registries"))
	_ = viper.BindPFlag("enforce_policy_freshness", rootCmd.PersistentFlags().Lookup("enforce-policy-freshness"))
}

func initConfig() {
	viper.SetEnvPrefix("PHOENIX")
	viper.AutomaticEnv()

	// Honor agent.toml so [fail_mode] mode and other file settings are read.
	// Flags and env still win over the file (viper precedence).
	viper.SetConfigType("toml")
	if home, err := os.UserHomeDir(); err == nil {
		viper.SetConfigFile(filepath.Join(home, ".config", "phoenix-firewall", "agent.toml"))
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				fmt.Fprintf(os.Stderr, "[phoenix-firewall] WARNING: failed to read config file: %v\n", err)
			}
		}
	}

	// Allow PHOENIX_FAIL_MODE to override the nested [fail_mode] mode key,
	// matching the env var the shim honors.
	_ = viper.BindEnv("fail_mode.mode", "PHOENIX_FAIL_MODE")
	viper.SetDefault("fail_mode.mode", "open")
}
