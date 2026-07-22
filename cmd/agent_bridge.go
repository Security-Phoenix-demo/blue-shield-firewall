package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/client"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/endpoint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const agentBridgeDiscoveryPath = "/etc/phoenix-firewall/agent-bridge.json"
const agentBridgeDiscoveryPathWindows = `C:\ProgramData\PhoenixFirewall\agent-bridge.json`

// agentBridgeConfig is the discovery file written by the supervisor.
type agentBridgeConfig struct {
	SocketPath string `json:"socket_path"`
	APIBaseURL string `json:"api_base_url"`
	Version    string `json:"version"`
}

// agentBridgeResult is the JSON printed to stdout by agent-bridge.
type agentBridgeResult struct {
	Verdict    string  `json:"verdict"`
	Action     string  `json:"action"`
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Source     string  `json:"source"`
}

var agentBridgeCmd = &cobra.Command{
	Use:   "agent-bridge",
	Short: "Route a package evaluation to the local v4 worker or backend",
	Long: `Reads the agent-bridge discovery file to find the local v4 worker.
If found, routes the evaluation locally (dedup with shim layer per R-FUNC-091).
Falls back to direct backend call if no local worker is available.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ecosystem, _ := cmd.Flags().GetString("ecosystem")
		pkg, _ := cmd.Flags().GetString("package")
		command, _ := cmd.Flags().GetString("command")
		return runAgentBridge(ecosystem, pkg, command)
	},
}

func runAgentBridge(ecosystem, pkg, command string) error {
	bridgeCfg, err := loadBridgeConfig()
	if err != nil {
		// No local worker — fall back to backend
		return agentBridgeFallback(ecosystem, pkg, command)
	}

	fmt.Fprintf(os.Stderr, "[agent-bridge] routing via local worker at %s\n", bridgeCfg.SocketPath)
	// TODO(B5): IPC call to worker over Unix socket / named pipe
	// For now: passthrough allow (will be wired in B5 implementation)
	_ = bridgeCfg
	printResult(agentBridgeResult{
		Verdict: "allow",
		Action:  "allow",
		Source:  "local_worker",
	})
	return nil
}

func loadBridgeConfig() (*agentBridgeConfig, error) {
	paths := discoveryPaths()
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var cfg agentBridgeConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				continue
			}
			return &cfg, nil
		}
	}
	return nil, fmt.Errorf("no bridge discovery file found (checked: %v)", paths)
}

func discoveryPaths() []string {
	paths := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "phoenix-firewall", "agent-bridge.json"))
	}
	paths = append(paths, agentBridgeDiscoveryPath)
	return paths
}

// agentBridgeFallback calls the Phoenix backend directly when no local worker is running.
func agentBridgeFallback(ecosystem, pkg, command string) error {
	apiURL := viper.GetString("api_url")
	apiKey := viper.GetString("api_key")
	if apiKey == "" {
		apiKey = os.Getenv("PHOENIX_API_KEY")
	}

	if apiKey == "" {
		// Fail-open when no key configured (matches R-FUNC-070 tier-default)
		fmt.Fprintf(os.Stderr, "[agent-bridge] no API key configured — failing open\n")
		printResult(agentBridgeResult{
			Verdict: "allow",
			Action:  "allow",
			Source:  "fallback_no_key",
		})
		return nil
	}

	// If pkg is empty, try to extract it from the full command string
	if pkg == "" {
		pkg = extractPackageFromCommand(command)
	}
	if pkg == "" {
		// Nothing to evaluate
		printResult(agentBridgeResult{
			Verdict: "allow",
			Action:  "allow",
			Source:  "fallback_no_package",
		})
		return nil
	}

	name, version := splitNameVersion(pkg)
	fmt.Fprintf(os.Stderr, "[agent-bridge] backend fallback: %s ecosystem=%s pkg=%s@%s\n",
		apiURL, ecosystem, name, version)

	c := client.New(apiURL, apiKey)
	if tenantID := viper.GetString("tenant_id"); tenantID != "" {
		c = c.WithTenantID(tenantID)
	}
	// device_id is required by the agent evaluate endpoint. Resolve it the same
	// way emitInstallActivity does: config, then env, then collected identity.
	deviceID := viper.GetString("device_id")
	if deviceID == "" {
		deviceID = os.Getenv("PHOENIX_DEVICE_ID")
	}
	if deviceID == "" {
		deviceID = endpoint.Collect().DeviceID
	}
	if deviceID != "" {
		c = c.WithDeviceID(deviceID)
	}
	result, err := c.Check(ecosystem, name, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agent-bridge] backend error: %v — failing open\n", err)
		printResult(agentBridgeResult{
			Verdict: "allow",
			Action:  "allow",
			Source:  "fallback_error",
			Reason:  err.Error(),
		})
		return nil
	}

	verdict := result.Verdict
	if verdict == "" {
		if result.Allowed {
			verdict = "safe"
		} else {
			verdict = "malicious"
		}
	}
	printResult(agentBridgeResult{
		Verdict:    verdict,
		Action:     result.Action,
		Score:      result.Score,
		Confidence: result.Confidence,
		Reason:     result.Reason,
		Source:     "backend_evaluate",
	})
	emitInstallActivity(c, ecosystem, name, version, command, result)
	return nil
}

func emitInstallActivity(c *client.Client, ecosystem, name, version, command string, result *client.CheckResult) {
	deviceID := viper.GetString("device_id")
	if deviceID == "" {
		deviceID = os.Getenv("PHOENIX_DEVICE_ID")
	}
	identity := endpoint.Collect()
	if deviceID == "" {
		deviceID = identity.DeviceID
	}
	if deviceID == "" || name == "" {
		return
	}
	metadata := map[string]interface{}{
		"source":  "agent-bridge",
		"action":  result.Action,
		"verdict": result.Verdict,
	}
	for key, value := range identity.Metadata("shim") {
		metadata[key] = value
	}
	teamID := viper.GetString("team_id")
	if teamID == "" {
		teamID = os.Getenv("PHOENIX_TEAM_ID")
	}
	if teamID != "" {
		metadata["team_id_hint"] = teamID
	}
	if err := c.SendActivity(client.EndpointActivityEvent{
		DeviceID:       deviceID,
		EventType:      "package_install",
		CollectorType:  "shim",
		OccurredAt:     time.Now().UTC().Format(time.RFC3339),
		Ecosystem:      ecosystem,
		PackageName:    name,
		PackageVersion: version,
		CommandText:    command,
		Metadata:       metadata,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[agent-bridge] activity emit failed: %v\n", err)
	}
}

// splitNameVersion splits "lodash@1.2.3" into ("lodash", "1.2.3").
// Handles npm scoped packages like "@scope/pkg@1.0.0".
func splitNameVersion(pkg string) (name, version string) {
	// npm scoped package: @scope/pkg@version — last @ after position 0
	if strings.HasPrefix(pkg, "@") {
		if idx := strings.LastIndex(pkg[1:], "@"); idx >= 0 {
			split := idx + 1
			return pkg[:split], pkg[split+1:]
		}
		return pkg, ""
	}
	if idx := strings.LastIndex(pkg, "@"); idx > 0 {
		return pkg[:idx], pkg[idx+1:]
	}
	return pkg, ""
}

// extractPackageFromCommand pulls a package name from a command string like
// "npm install lodash" or "pip install requests==2.28.0".
func extractPackageFromCommand(cmd string) string {
	parts := strings.Fields(strings.TrimSpace(cmd))
	// Skip PM binary and subcommand ("npm install", "pip install", "cargo add", etc.)
	if len(parts) >= 3 {
		// Return the first non-flag argument
		for _, p := range parts[2:] {
			if !strings.HasPrefix(p, "-") {
				return p
			}
		}
	}
	return ""
}

func printResult(r agentBridgeResult) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func init() {
	agentBridgeCmd.Flags().String("ecosystem", "auto", "Package ecosystem (npm, pip, cargo, etc.)")
	agentBridgeCmd.Flags().String("package", "", "Package name to evaluate (name@version)")
	agentBridgeCmd.Flags().String("command", "", "Full install command string")
	agentBridgeCmd.Flags().String("trigger", "bridge", "Trigger source (bridge, mcp, hook)")
	rootCmd.AddCommand(agentBridgeCmd)
}
