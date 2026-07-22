package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/policy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/proxy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/service"
	"github.com/spf13/cobra"
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Run as a managed system service (endpoint mode)",
	Long: `Starts the phoenix-firewall in endpoint mode.

Loads configuration from ~/.config/phoenix-firewall/agent.toml, ensures the
MITM CA certificate exists, and starts the local MITM proxy on port 8080.

The package manager shims (installed by 'phoenix-firewall init') set
HTTPS_PROXY=http://127.0.0.1:8080 and PM-specific CA env vars so that
all registry traffic is intercepted and evaluated before installation.

Subcommands manage the OS user service (LaunchAgent / systemd --user / schtasks):
  phoenix-firewall system install   — write service definition
  phoenix-firewall system start     — install and activate at login
  phoenix-firewall system stop      — stop running service
  phoenix-firewall system uninstall — remove service definition
  phoenix-firewall system status    — show service status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSystemMode()
	},
}

var systemInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Write the OS user service definition (does not start it)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return installService()
	},
}

var systemStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Install and activate the OS user service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return startService()
	},
}

var systemStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running OS user service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return stopService()
	},
}

var systemUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the OS user service definition",
	RunE: func(cmd *cobra.Command, args []string) error {
		return uninstallService()
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show OS user service status",
	RunE: func(cmd *cobra.Command, args []string) error {
		return showStatus()
	},
}

func runSystemMode() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home dir: %w", err)
	}
	cfgDir := filepath.Join(home, ".config", "phoenix-firewall")

	cfg := loadConfigWithAgentTOML()

	log.Printf("[phoenix-firewall] starting userland proxy on 127.0.0.1:%d", cfg.Port)
	if cfg.StrictMode {
		log.Println("[phoenix-firewall] strict mode: warn treated as block; fail-closed on API error")
	}

	// Ensure the MITM CA certificate exists in the user config directory
	ca, err := proxy.EnsureCA(cfgDir)
	if err != nil {
		return fmt.Errorf("ensure CA: %w", err)
	}
	log.Printf("[phoenix-firewall] CA ready at %s/phoenix-ca.crt", cfgDir)

	// Load fallback feed if configured (offline checking parity with `proxy`).
	var fallbackFeed *proxy.FallbackFeed
	if cfg.FallbackFeed != "" {
		feed, feedErr := proxy.LoadFallbackFeed(cfg.FallbackFeed)
		if feedErr != nil {
			return fmt.Errorf("load fallback feed: %w", feedErr)
		}
		log.Printf("[phoenix-firewall] loaded fallback feed with %d entries", feed.Len())
		fallbackFeed = feed
	}

	// Optionally enforce policy freshness (fail-closed when policy is stale).
	var policySyncer *policy.Syncer
	if cfg.EnforcePolicyFreshness {
		policySyncer = policy.NewSyncer(cfg.APIUrl, cfg.APIKey)
		policySyncer.Start()
		defer policySyncer.Stop()
		log.Println("[phoenix-firewall] policy freshness enforcement: ON (blocks installs when policy stale > 24h)")
	}

	stopHeartbeat := startEndpointHeartbeat(cfg, nil)
	defer stopHeartbeat()

	srv := proxy.NewServer(cfg)
	srv.SetCA(ca)

	// Wire strict-mode / fallback / policy gate onto the handler. Shared with the
	// `proxy` command so endpoint (service) mode enforces identically.
	srv.ConfigureHandler(func(h *proxy.RequestHandler) {
		applyHandlerConfig(h, cfg, nil, fallbackFeed, policySyncer)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("[phoenix-firewall] received shutdown signal, stopping proxy")
		cancel()
	}()

	return srv.StartWithContext(ctx)
}

func installService() error {
	mgr := service.New()
	if err := mgr.Install(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	fmt.Println("[phoenix-firewall] service definition written")
	fmt.Println("[phoenix-firewall] run 'phoenix-firewall system start' to activate at login")
	return nil
}

func startService() error {
	mgr := service.New()
	if err := mgr.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("[phoenix-firewall] service started and enabled at login")
	return nil
}

func stopService() error {
	mgr := service.New()
	if err := mgr.Stop(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	fmt.Println("[phoenix-firewall] service stopped")
	return nil
}

func uninstallService() error {
	mgr := service.New()
	if err := mgr.Uninstall(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}
	fmt.Println("[phoenix-firewall] service removed")
	return nil
}

func showStatus() error {
	mgr := service.New()
	out, err := mgr.Status()
	if err != nil {
		// Status check errors are informational — print anyway
		fmt.Fprintf(os.Stderr, "[phoenix-firewall] status check error: %v\n", err)
	}
	if out != "" {
		fmt.Print(out)
	}
	return nil
}

func init() {
	systemCmd.AddCommand(systemInstallCmd)
	systemCmd.AddCommand(systemStartCmd)
	systemCmd.AddCommand(systemStopCmd)
	systemCmd.AddCommand(systemUninstallCmd)
	systemCmd.AddCommand(systemStatusCmd)
	rootCmd.AddCommand(systemCmd)
}
