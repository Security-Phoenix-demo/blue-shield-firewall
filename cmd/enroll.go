package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Activate phoenix-firewall with your API key (userland enrollment)",
	Long: `Stores your Phoenix API key in ~/.config/phoenix-firewall/agent.toml.
No MDM, no root, no bootstrap tokens required.

Get your API key at https://phxintel.security.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		apiKey, _ := cmd.Flags().GetString("api-key")
		apiURL, _ := cmd.Flags().GetString("api-url")
		tenantID, _ := cmd.Flags().GetString("tenant-id")
		deviceID, _ := cmd.Flags().GetString("device-id")
		teamID, _ := cmd.Flags().GetString("team-id")
		return runEnroll(apiKey, apiURL, tenantID, deviceID, teamID)
	},
}

func runEnroll(apiKey, apiURL, tenantID, deviceID, teamID string) error {
	if apiKey == "" {
		return fmt.Errorf("--api-key is required; get yours at https://phxintel.security")
	}
	if apiURL == "" {
		apiURL = "https://api.phxintel.security"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfgDir := filepath.Join(home, ".config", "phoenix-firewall")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tomlPath := filepath.Join(cfgDir, "agent.toml")
	var existing string
	if data, err := os.ReadFile(tomlPath); err == nil {
		existing = string(data)
	}

	// Update or insert api_key and api_url lines
	existing = upsertTOMLLine(existing, "api_key", fmt.Sprintf("%q", apiKey))
	existing = upsertTOMLLine(existing, "api_url", fmt.Sprintf("%q", apiURL))
	if tenantID != "" {
		existing = upsertTOMLLine(existing, "tenant_id", fmt.Sprintf("%q", tenantID))
	}
	if deviceID != "" {
		existing = upsertTOMLLine(existing, "device_id", fmt.Sprintf("%q", deviceID))
	}
	if teamID != "" {
		existing = upsertTOMLLine(existing, "team_id", fmt.Sprintf("%q", teamID))
	}

	if err := os.WriteFile(tomlPath, []byte(existing), 0600); err != nil {
		return fmt.Errorf("write agent.toml: %w", err)
	}
	fmt.Printf("[phoenix-firewall] enrolled: API key written to %s\n", tomlPath)
	if teamID != "" {
		fmt.Println("[phoenix-firewall] team_id stored as a non-authoritative collector hint; Phoenix resolves access server-side.")
	}
	fmt.Println("[phoenix-firewall] you're good to go — shims will evaluate packages via Phoenix.")
	return nil
}

// upsertTOMLLine replaces key = value in a TOML string, or appends it.
func upsertTOMLLine(content, key, quotedValue string) string {
	newLine := key + " = " + quotedValue
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+" ") || strings.HasPrefix(trimmed, key+"=") {
			lines[i] = newLine
			return strings.Join(lines, "\n")
		}
	}
	// Key not found — append
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + newLine + "\n"
}

func init() {
	enrollCmd.Flags().String("api-key", "", "Your Phoenix API key (required)")
	enrollCmd.Flags().String("api-url", "https://api.phxintel.security", "Phoenix API base URL")
	enrollCmd.Flags().String("tenant-id", "", "Tenant ID (optional; auto-detected from API key)")
	enrollCmd.Flags().String("device-id", "", "Device ID (optional; auto-generated if not set)")
	enrollCmd.Flags().String("team-id", "", "Team ID hint (optional; metadata only, not authorization)")
	_ = enrollCmd.MarkFlagRequired("api-key")
	rootCmd.AddCommand(enrollCmd)
}
