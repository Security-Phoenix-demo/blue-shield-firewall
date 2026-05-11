package cmd

import (
	"encoding/json"
	"fmt"
	"os"

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
	fmt.Println(`{"verdict":"allow","source":"local_worker"}`)
	return nil
}

func loadBridgeConfig() (*agentBridgeConfig, error) {
	path := agentBridgeDiscoveryPath
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("bridge discovery file not found: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg agentBridgeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func agentBridgeFallback(ecosystem, pkg, command string) error {
	apiURL := viper.GetString("api_url")
	apiKey := os.Getenv("PHOENIX_API_KEY")
	if apiKey == "" {
		// Fail-open when no key configured (matches R-FUNC-070 tier-default)
		fmt.Println(`{"verdict":"allow","source":"fallback_no_key"}`)
		return nil
	}
	fmt.Fprintf(os.Stderr, "[agent-bridge] fallback to backend %s ecosystem=%s package=%s\n", apiURL, ecosystem, pkg)
	// TODO: implement HTTP call to /api/v1/firewall/agent/evaluate
	fmt.Println(`{"verdict":"allow","source":"backend_fallback"}`)
	_ = command
	return nil
}

func init() {
	agentBridgeCmd.Flags().String("ecosystem", "auto", "Package ecosystem (npm, pip, cargo, etc.)")
	agentBridgeCmd.Flags().String("package", "", "Package name to evaluate")
	agentBridgeCmd.Flags().String("command", "", "Full install command string")
	agentBridgeCmd.Flags().String("trigger", "bridge", "Trigger source (bridge, mcp, hook)")
	rootCmd.AddCommand(agentBridgeCmd)
}
