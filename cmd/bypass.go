// Package cmd — phoenix-firewall bypass subcommand.
//
// The package-manager shims consult `bypass verify` before skipping the
// firewall proxy. Authorization is anchored server-side (the agent holds no
// signing key), so a bypass cannot be forged locally and the check fails
// closed: on any error or denial the shim routes the install through the proxy.
package cmd

import (
	"fmt"
	"os"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/client"
	"github.com/spf13/cobra"
)

// bypassTokenEnv is the environment variable the shims set to request a bypass.
const bypassTokenEnv = "PHOENIX_FIREWALL_BYPASS_TOKEN"

var bypassCmd = &cobra.Command{
	Use:   "bypass",
	Short: "Manage firewall bypass authorization",
}

var bypassVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Check (server-side) whether the bypass token authorizes skipping interception",
	Long: `Reads the bypass token from $PHOENIX_FIREWALL_BYPASS_TOKEN and asks the
Phoenix firewall API whether it authorizes bypassing interception for the
current API credentials.

Exit code 0 = authorized (the shim may run the package manager directly);
non-zero = denied or error (the shim must route through the firewall). The
check fails closed. Invoked automatically by the shims; rarely run by hand.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		token := os.Getenv(bypassTokenEnv)
		if token == "" {
			return fmt.Errorf("no bypass token set in %s", bypassTokenEnv)
		}

		cfg := agentConfig()
		if cfg.APIKey == "" {
			return fmt.Errorf("no API key configured (run 'phoenix-firewall enroll')")
		}

		c := client.New(cfg.APIUrl, cfg.APIKey)
		authorized, reason, err := c.VerifyBypass(token)
		if err != nil {
			return fmt.Errorf("bypass not authorized (fail-closed): %w", err)
		}
		if !authorized {
			if reason == "" {
				reason = "denied by firewall policy"
			}
			return fmt.Errorf("bypass not authorized: %s", reason)
		}

		fmt.Fprintln(os.Stderr, "[phoenix-firewall] bypass authorized")
		return nil
	},
}

func init() {
	bypassCmd.AddCommand(bypassVerifyCmd)
	rootCmd.AddCommand(bypassCmd)
}
