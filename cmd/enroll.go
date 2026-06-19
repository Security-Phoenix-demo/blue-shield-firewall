package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/client"
	"github.com/spf13/cobra"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Activate phoenix-firewall with your API key (userland enrollment)",
	Long: `Stores your Phoenix API key in ~/.config/phoenix-firewall/agent.toml
and registers this device with the Phoenix backend.

Get your API key at https://phxintel.security.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		apiKey, _ := cmd.Flags().GetString("api-key")
		apiURL, _ := cmd.Flags().GetString("api-url")
		tenantID, _ := cmd.Flags().GetString("tenant-id")
		deviceID, _ := cmd.Flags().GetString("device-id")
		bootstrap, _ := cmd.Flags().GetString("bootstrap-token")
		return runEnroll(apiKey, apiURL, tenantID, deviceID, bootstrap)
	},
}

func runEnroll(apiKey, apiURL, tenantID, deviceID, bootstrap string) error {
	if apiKey == "" && bootstrap == "" {
		return fmt.Errorf("--api-key or --bootstrap-token is required; get yours at https://phxintel.security")
	}
	if apiURL == "" {
		apiURL = "https://api.phxintel.security"
	}
	if deviceID == "" {
		deviceID = defaultDeviceID()
	}

	// Register with the backend (best-effort). On comms failure we keep local
	// config so the user is not blocked, but we tell them clearly.
	c := client.New(apiURL, apiKey)
	if resp, err := c.Enroll(deviceID, bootstrap, enrollMetadata()); err != nil {
		fmt.Fprintf(os.Stderr, "[phoenix-firewall] WARNING: backend enrollment failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "[phoenix-firewall] continuing with local config; re-run 'phoenix-firewall enroll' once connectivity is restored")
	} else {
		if resp.APIKey != "" {
			apiKey = resp.APIKey // backend issued an agent key — persist that
		}
		if resp.DeviceID != "" {
			deviceID = resp.DeviceID
		}
		fmt.Printf("[phoenix-firewall] registered device %s with backend\n", deviceID)
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

	// Update or insert api_key, api_url, device_id, tenant_id lines
	if apiKey != "" {
		existing = upsertTOMLLine(existing, "api_key", fmt.Sprintf("%q", apiKey))
	}
	existing = upsertTOMLLine(existing, "api_url", fmt.Sprintf("%q", apiURL))
	if tenantID != "" {
		existing = upsertTOMLLine(existing, "tenant_id", fmt.Sprintf("%q", tenantID))
	}
	existing = upsertTOMLLine(existing, "device_id", fmt.Sprintf("%q", deviceID))

	if err := os.WriteFile(tomlPath, []byte(existing), 0600); err != nil {
		return fmt.Errorf("write agent.toml: %w", err)
	}
	// Explicitly chmod to 0600 — WriteFile perm only applies on O_CREATE;
	// a pre-existing file retains its original permissions.
	_ = os.Chmod(tomlPath, 0600)
	fmt.Printf("[phoenix-firewall] enrolled: config written to %s\n", tomlPath)
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

// defaultDeviceID derives a stable-ish device id from the hostname.
func defaultDeviceID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return "dev-" + h
	}
	return "dev-unknown"
}

// enrollMetadata reports basic host metadata to the backend at enroll time.
func enrollMetadata() map[string]string {
	host, _ := os.Hostname()
	return map[string]string{
		"hostname": host,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	}
}

func init() {
	enrollCmd.Flags().String("api-key", "", "Your Phoenix API key")
	enrollCmd.Flags().String("api-url", "https://api.phxintel.security", "Phoenix API base URL")
	enrollCmd.Flags().String("tenant-id", "", "Tenant ID (optional; auto-detected from API key)")
	enrollCmd.Flags().String("device-id", "", "Device ID (optional; auto-generated if not set)")
	enrollCmd.Flags().String("bootstrap-token", "", "One-time bootstrap token for backend enrollment (alternative to --api-key)")
	// api-key is validated in runEnroll (bootstrap token may stand in for it)
	rootCmd.AddCommand(enrollCmd)
}
