package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/client"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/endpoint"
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
		bootstrapToken, _ := cmd.Flags().GetString("bootstrap-token")
		return runEnrollWithOptions(enrollOptions{
			APIKey:         apiKey,
			APIURL:         apiURL,
			TenantID:       tenantID,
			DeviceID:       deviceID,
			TeamID:         teamID,
			BootstrapToken: bootstrapToken,
			Identity:       endpoint.Collect(),
		})
	},
}

func runEnroll(apiKey, apiURL, tenantID, deviceID, teamID string) error {
	return runEnrollWithOptions(enrollOptions{
		APIKey:   apiKey,
		APIURL:   apiURL,
		TenantID: tenantID,
		DeviceID: deviceID,
		TeamID:   teamID,
		Identity: endpoint.Collect(),
	})
}

type enrollOptions struct {
	APIKey         string
	APIURL         string
	TenantID       string
	DeviceID       string
	TeamID         string
	BootstrapToken string
	Identity       endpoint.Identity
}

func runEnrollWithOptions(opts enrollOptions) error {
	if opts.APIKey == "" {
		return fmt.Errorf("--api-key is required; get yours at https://phxintel.security")
	}
	if opts.APIURL == "" {
		opts.APIURL = "https://api.phxintel.security"
	}
	if opts.DeviceID == "" {
		opts.DeviceID = opts.Identity.DeviceID
	}
	if opts.BootstrapToken != "" {
		enrolled, err := client.New(opts.APIURL, opts.APIKey).EnrollDevice(client.EnrollRequest{
			TenantID:       opts.TenantID,
			DeviceID:       opts.DeviceID,
			BootstrapToken: opts.BootstrapToken,
			Hostname:       opts.Identity.Hostname,
			Platform:       runtime.GOOS,
			AgentVersion:   version,
			TeamID:         opts.TeamID,
			Metadata:       opts.Identity.Metadata("shim"),
		})
		if err != nil {
			return err
		}
		if enrolled.APIKey != "" {
			opts.APIKey = enrolled.APIKey
		}
		if enrolled.DeviceID != "" {
			opts.DeviceID = enrolled.DeviceID
		}
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
	existing = upsertTOMLLine(existing, "api_key", fmt.Sprintf("%q", opts.APIKey))
	existing = upsertTOMLLine(existing, "api_url", fmt.Sprintf("%q", opts.APIURL))
	if opts.TenantID != "" {
		existing = upsertTOMLLine(existing, "tenant_id", fmt.Sprintf("%q", opts.TenantID))
	}
	if opts.DeviceID != "" {
		existing = upsertTOMLLine(existing, "device_id", fmt.Sprintf("%q", opts.DeviceID))
	}
	if opts.TeamID != "" {
		existing = upsertTOMLLine(existing, "team_id", fmt.Sprintf("%q", opts.TeamID))
	}
	existing = upsertTOMLLine(existing, "endpoint_id_source", fmt.Sprintf("%q", opts.Identity.IDSource))
	existing = upsertTOMLLine(existing, "hostname", fmt.Sprintf("%q", opts.Identity.Hostname))
	existing = upsertTOMLLine(existing, "primary_mac", fmt.Sprintf("%q", opts.Identity.PrimaryMAC))
	existing = upsertTOMLLine(existing, "logged_in_user", fmt.Sprintf("%q", opts.Identity.LoggedInUser))

	if err := os.WriteFile(tomlPath, []byte(existing), 0600); err != nil {
		return fmt.Errorf("write agent.toml: %w", err)
	}
	fmt.Printf("[phoenix-firewall] enrolled: API key written to %s\n", tomlPath)
	if opts.TeamID != "" {
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
	enrollCmd.Flags().String("bootstrap-token", "", "Optional one-time bootstrap token for backend device registration")
	_ = enrollCmd.MarkFlagRequired("api-key")
	rootCmd.AddCommand(enrollCmd)
}
