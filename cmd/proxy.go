package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/policy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/proxy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/telemetry"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start the MITM proxy server",
	Long:  `Start an HTTP proxy that intercepts package manager requests and checks them against the Phoenix firewall API.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		warnIfAPIKeyFlag(cmd)
		cfg := loadConfigWithAgentTOML()

		// Resolve CA directory
		caDir, _ := cmd.Flags().GetString("ca-dir")
		if caDir == "" {
			caDir = proxy.DefaultCADir()
		}

		trust, _ := cmd.Flags().GetBool("trust")

		// Ensure CA exists. All human-readable output goes to STDERR so that
		// stdout stays clean and the quick-start flow (`eval "$(phoenix-firewall
		// env)"`) is never corrupted by log lines.
		fmt.Fprintf(os.Stderr, "CA directory: %s\n", caDir)
		ca, err := proxy.EnsureCA(caDir)
		if err != nil {
			return fmt.Errorf("ensure CA: %w", err)
		}
		fmt.Fprintln(os.Stderr, "CA certificate ready.")

		// Optionally inject into system trust store
		if trust {
			certPath := filepath.Join(caDir, "phoenix-ca.crt")
			if err := proxy.InjectCA(certPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: auto trust injection failed: %v\n", err)
				fmt.Fprintln(os.Stderr, "The proxy will still work if you configure your package manager to trust the CA manually.")
			}
		}

		// Load fallback feed if configured
		var fallbackFeed *proxy.FallbackFeed
		if cfg.FallbackFeed != "" {
			feed, feedErr := proxy.LoadFallbackFeed(cfg.FallbackFeed)
			if feedErr != nil {
				return fmt.Errorf("load fallback feed: %w", feedErr)
			}
			log.Printf("Loaded fallback feed with %d entries from %s", feed.Len(), cfg.FallbackFeed)
			fallbackFeed = feed
		}

		// Create reporter if report path configured or CI mode enabled
		var reporter *proxy.Reporter
		if cfg.ReportPath != "" || cfg.CIMode {
			reporter = proxy.NewReporter()
		}

		fmt.Fprintf(os.Stderr, "Starting proxy on :%d\n", cfg.Port)
		fmt.Fprintf(os.Stderr, "To route this shell through it, run:  eval \"$(phoenix-firewall env)\"\n")
		if cfg.StrictMode {
			fmt.Fprintln(os.Stderr, "Strict mode: warn actions will be treated as block")
		}
		if cfg.CIMode {
			fmt.Fprintln(os.Stderr, "CI mode: will exit with code 1 if any packages blocked")
		}

		// Optionally enforce policy freshness (fail-closed when policy is stale).
		var policySyncer *policy.Syncer
		if cfg.EnforcePolicyFreshness {
			policySyncer = policy.NewSyncer(cfg.APIUrl, cfg.APIKey)
			policySyncer.Start()
			defer policySyncer.Stop()
			fmt.Fprintln(os.Stderr, "Policy freshness enforcement: ON (blocks installs when policy stale > 24h)")
		}

		stopHeartbeat := startEndpointHeartbeat(cfg)
		defer stopHeartbeat()

		srv := proxy.NewServer(cfg)
		srv.SetCA(ca)

		// Identity/health endpoint for the shim handshake.
		hs := proxy.NewHealthState(version, cfg.Port, cfg.FailMode)
		srv.SetHealthState(hs)

		// Readiness: drive backend reachability from heartbeat results and warn
		// clearly when the Phoenix backend cannot be reached.
		tenantID := viper.GetString("tenant_id")
		deviceID := viper.GetString("device_id")
		hb := telemetry.NewHeartbeatSender(cfg.APIUrl, cfg.APIKey, tenantID, deviceID)
		hb.OnResult = func(ok bool) {
			hs.SetBackendReachable(ok)
			if !ok {
				log.Printf("[phoenix-firewall] WARNING: cannot reach Phoenix backend at %s — operating in fail_mode=%s", cfg.APIUrl, cfg.FailMode)
			}
		}
		hb.Start(5 * time.Minute)
		defer hb.Stop()

		fmt.Printf("[phoenix-firewall] fail_mode=%s; health endpoint at http://127.0.0.1:%d%s\n", cfg.FailMode, cfg.Port, proxy.HealthPath)

		// Configure the handler with new features after server creation
		srv.ConfigureHandler(func(h *proxy.RequestHandler) {
			h.SetFailMode(cfg.FailMode)
			applyHandlerConfig(h, cfg, reporter, fallbackFeed, policySyncer)
		})

		// Set up graceful shutdown via signal
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			log.Println("Received shutdown signal")
			cancel()
		}()

		srvErr := srv.StartWithContext(ctx)

		// Write report on shutdown
		if reporter != nil && cfg.ReportPath != "" {
			if writeErr := reporter.Write(cfg.ReportPath); writeErr != nil {
				log.Printf("Warning: failed to write report: %v", writeErr)
			} else {
				log.Printf("Report written to %s", cfg.ReportPath)
			}
		}

		// Print summary if reporter exists
		if reporter != nil {
			summary := reporter.Summary()
			fmt.Fprintf(os.Stderr, "\nScan Summary: %d total, %d blocked, %d warned, %d allowed\n",
				summary.TotalPackages, summary.Blocked, summary.Warned, summary.Allowed)
		}

		// CI mode: exit with code 1 if any packages were blocked
		if cfg.CIMode && reporter != nil && reporter.HasBlocked() {
			fmt.Fprintln(os.Stderr, "CI mode: blocked packages detected, exiting with code 1")
			os.Exit(1)
		}

		return srvErr
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().String("ca-dir", "", "Directory for CA certificate and key (default: ~/.config/phoenix-firewall/)")
	proxyCmd.Flags().Bool("trust", false, "Attempt to inject CA into system trust store (requires sudo)")
}
