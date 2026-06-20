// Package cmd — phoenix-firewall rules subcommand.
//
// Retrieves the authenticated user's firewall rules from the Phoenix Security
// API. Useful for local previewing, CI debugging, and validating that a
// `phx_fw_*` self-service key has the expected rule set attached.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Retrieve and manage firewall rules attached to your account",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List firewall rules for the authenticated user",
	Long: `Retrieves the firewall rules attached to the API key (or JWT) in use.

Uses GET /api/v1/firewall/rules. Accepts a phx_fw_* Malware Firewall key, a
phx_whk_* Webhook key, or a Cognito JWT.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		apiURL := viper.GetString("api_url")
		apiKey := viper.GetString("api_key")
		if apiKey == "" {
			apiKey = os.Getenv("PHOENIX_API_KEY")
		}
		if apiKey == "" {
			return fmt.Errorf("api key not set: pass --api-key or export PHOENIX_API_KEY")
		}

		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		asJSON, _ := cmd.Flags().GetBool("json")

		url := fmt.Sprintf("%s/api/v1/firewall/rules?limit=%d&offset=%d", apiURL, limit, offset)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		// Both auth headers are accepted server-side; X-API-Key is the
		// canonical self-service path.
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		if resp.StatusCode >= 300 {
			return fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
		}

		if asJSON {
			fmt.Println(string(body))
			return nil
		}

		var parsed struct {
			Items []struct {
				RuleID   string `json:"rule_id"`
				Name     string `json:"name"`
				Action   string `json:"action"`
				Enabled  bool   `json:"enabled"`
				Priority int    `json:"priority"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			// Fall back to raw output.
			fmt.Println(string(body))
			return nil
		}

		fmt.Printf("Phoenix Security Blue Shield - Firewall rules — %d total\n\n", parsed.Total)
		fmt.Printf("%-36s  %-30s  %-15s  %-8s  %s\n", "RULE_ID", "NAME", "ACTION", "ENABLED", "PRIORITY")
		for _, r := range parsed.Items {
			fmt.Printf("%-36s  %-30s  %-15s  %-8t  %d\n",
				r.RuleID, truncate(r.Name, 30), r.Action, r.Enabled, r.Priority)
		}
		return nil
	},
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func init() {
	rulesListCmd.Flags().Int("limit", 100, "Maximum rules to return (1-500)")
	rulesListCmd.Flags().Int("offset", 0, "Offset for pagination")
	rulesListCmd.Flags().Bool("json", false, "Emit raw JSON instead of a table")

	rulesCmd.AddCommand(rulesListCmd)
	rootCmd.AddCommand(rulesCmd)
}
