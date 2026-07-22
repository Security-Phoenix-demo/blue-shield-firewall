package cmd

import (
	"errors"
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
	Long: `Stores your Phoenix API key in ~/.config/phoenix-firewall/agent.toml
and registers this device with the Phoenix backend.

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
	if opts.APIKey == "" && opts.BootstrapToken == "" {
		return fmt.Errorf("--api-key or --bootstrap-token is required; get yours at https://phxintel.security")
	}
	if opts.APIURL == "" {
		opts.APIURL = "https://phxintel.security"
	}
	if opts.DeviceID == "" {
		opts.DeviceID = opts.Identity.DeviceID
	}
	if opts.DeviceID == "" {
		opts.DeviceID = defaultDeviceID()
	}

	// Backend enrollment always sends the FULL v4 payload (hostname, platform,
	// agent_version) so the backend EnrollRequest contract is satisfied whether
	// we authenticate with a one-time bootstrap token or an existing API key.
	// When no bootstrap token is present, bootstrap_token is omitted from the
	// body and the backend authorizes enrollment via the API key alone.
	enrollReq := client.EnrollRequest{
		TenantID:       opts.TenantID,
		DeviceID:       opts.DeviceID,
		BootstrapToken: opts.BootstrapToken,
		Hostname:       opts.Identity.Hostname,
		Platform:       runtime.GOOS,
		AgentVersion:   version,
		TeamID:         opts.TeamID,
		Metadata:       opts.Identity.Metadata("shim"),
	}

	// backendEnrolled records whether the backend actually registered this
	// device, so the final message reflects reality instead of always claiming
	// "you're good to go".
	backendEnrolled := false

	if opts.BootstrapToken != "" {
		// One-time bootstrap token: enrollment must succeed (the token is
		// single-use), so surface any error to the caller.
		enrolled, err := client.New(opts.APIURL, opts.APIKey).EnrollDevice(enrollReq)
		if err != nil {
			return err
		}
		if enrolled.APIKey != "" {
			opts.APIKey = enrolled.APIKey
		}
		if enrolled.DeviceID != "" {
			opts.DeviceID = enrolled.DeviceID
		}
		backendEnrolled = true
	} else {
		// API-key enrollment. A definitive auth rejection (401/403) means the
		// key is invalid: fail hard WITHOUT touching local config, so we never
		// overwrite a working key or claim success on a rejected one. A
		// transient failure (network / 5xx) is tolerated best-effort.
		resp, err := client.New(opts.APIURL, opts.APIKey).EnrollDevice(enrollReq)
		switch {
		case err == nil:
			if resp.APIKey != "" {
				opts.APIKey = resp.APIKey // backend issued a device-bound key — persist that
			}
			if resp.DeviceID != "" {
				opts.DeviceID = resp.DeviceID
			}
			backendEnrolled = true
			fmt.Printf("[phoenix-firewall] registered device %s with backend\n", opts.DeviceID)
		default:
			var apiErr *client.APIError
			if errors.As(err, &apiErr) && apiErr.IsAuth() {
				return fmt.Errorf("enrollment rejected by %s: the API key is invalid or expired (HTTP %d) — check the key (enrollment keys look like phx_fw_...; get one at https://phxintel.security). Local config was left unchanged: %w",
					opts.APIURL, apiErr.StatusCode, err)
			}
			fmt.Fprintf(os.Stderr, "[phoenix-firewall] WARNING: backend enrollment could not be completed: %v\n", err)
			fmt.Fprintln(os.Stderr, "[phoenix-firewall] saving local config unverified; re-run 'phoenix-firewall enroll' once connectivity is restored")
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
	if opts.APIKey != "" {
		existing = upsertTOMLLine(existing, "api_key", fmt.Sprintf("%q", opts.APIKey))
	}
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
	// Explicitly chmod to 0600 — WriteFile perm only applies on O_CREATE;
	// a pre-existing file retains its original permissions.
	_ = os.Chmod(tomlPath, 0600)
	fmt.Printf("[phoenix-firewall] config written to %s\n", tomlPath)
	if opts.TeamID != "" {
		fmt.Println("[phoenix-firewall] team_id stored as a non-authoritative collector hint; Phoenix resolves access server-side.")
	}
	if backendEnrolled {
		fmt.Println("[phoenix-firewall] you're good to go — shims will evaluate packages via Phoenix.")
	} else {
		fmt.Println("[phoenix-firewall] NOTE: device is NOT yet registered with the backend — re-run 'phoenix-firewall enroll' once connectivity is restored.")
	}
	return nil
}

// upsertTOMLLine replaces key = value in a TOML string, or inserts it.
// New keys are inserted before the first [section] header so they remain
// top-level keys rather than being silently placed inside a TOML table.
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
	// Key not found — insert before the first [section] header so the new
	// key lands at the top level and is not absorbed into a TOML table.
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			out := make([]string, 0, len(lines)+1)
			out = append(out, lines[:i]...)
			out = append(out, newLine)
			out = append(out, lines[i:]...)
			return strings.Join(out, "\n")
		}
	}
	// No section header — append at end.
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

func init() {
	enrollCmd.Flags().String("api-key", "", "Your Phoenix API key (required unless --bootstrap-token is provided)")
	enrollCmd.Flags().String("api-url", "https://phxintel.security", "Phoenix API base URL")
	enrollCmd.Flags().String("tenant-id", "", "Tenant ID (optional; auto-detected from API key)")
	enrollCmd.Flags().String("device-id", "", "Device ID (optional; auto-generated if not set)")
	enrollCmd.Flags().String("team-id", "", "Team ID hint (optional; metadata only, not authorization)")
	enrollCmd.Flags().String("bootstrap-token", "", "One-time bootstrap token for backend enrollment (alternative to --api-key)")
	// api-key validation is done in runEnrollWithOptions (bootstrap token may stand in for it)
	rootCmd.AddCommand(enrollCmd)
}
