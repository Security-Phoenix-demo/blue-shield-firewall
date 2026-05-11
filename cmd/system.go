package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/config"
	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

Use 'phoenix-firewall system install' to register as an OS user service.
Use 'phoenix-firewall system start|stop|status' to manage it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSystemMode()
	},
}

var systemInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install phoenix-firewall as an OS user service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return installService()
	},
}

var systemUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the phoenix-firewall OS user service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return uninstallService()
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show service status and agent health",
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

	// Supplement viper with values from agent.toml (CLI flags and PHOENIX_* env vars
	// take precedence over toml, so we read toml into a local viper instance and
	// back-fill only the fields that weren't already set via flags/env).
	localViper := viper.New()
	localViper.SetConfigFile(filepath.Join(cfgDir, "agent.toml"))
	localViper.SetConfigType("toml")
	_ = localViper.ReadInConfig()

	cfg := config.Load()
	if cfg.APIKey == "" {
		cfg.APIKey = localViper.GetString("api_key")
	}
	// root.go defaults api-url to http://localhost:8000 (dev); prefer agent.toml value
	if cfg.APIUrl == "http://localhost:8000" {
		if u := localViper.GetString("api_url"); u != "" {
			cfg.APIUrl = u
		}
	}

	log.Printf("[phoenix-firewall] starting userland proxy on 127.0.0.1:%d", cfg.Port)

	// Ensure the MITM CA certificate exists in the user config directory
	ca, err := proxy.EnsureCA(cfgDir)
	if err != nil {
		return fmt.Errorf("ensure CA: %w", err)
	}
	log.Printf("[phoenix-firewall] CA ready at %s/phoenix-ca.crt", cfgDir)

	srv := proxy.NewServer(cfg)
	srv.SetCA(ca)

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
	fmt.Fprintln(os.Stdout, "[phoenix-firewall] installing OS user service (not yet implemented — see internal/service/)")
	return nil
}

func uninstallService() error {
	fmt.Fprintln(os.Stdout, "[phoenix-firewall] uninstalling OS user service (not yet implemented — see internal/service/)")
	return nil
}

func showStatus() error {
	fmt.Fprintln(os.Stdout, "[phoenix-firewall] service status: not yet implemented")
	return nil
}

func init() {
	systemCmd.AddCommand(systemInstallCmd)
	systemCmd.AddCommand(systemUninstallCmd)
	systemCmd.AddCommand(systemStatusCmd)
	rootCmd.AddCommand(systemCmd)
}
