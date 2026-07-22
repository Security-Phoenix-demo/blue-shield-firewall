package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Print shell exports to route the current shell through the proxy",
	Long: `Print the environment variables that route this shell's package-manager
and HTTPS traffic through a running 'phoenix-firewall proxy', trusting its CA.

Usage:
  eval "$(phoenix-firewall env)"

This sets HTTPS_PROXY/HTTP_PROXY to the local proxy and points each supported
package manager's CA variable at the Phoenix CA certificate, so intercepted TLS
is trusted. It is the shell-wide equivalent of the per-command shims installed
by 'phoenix-firewall init'. Undo it by opening a new shell, or unset the printed
variables.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		port := viper.GetInt("port")
		if port == 0 {
			port = 8080
		}
		caDir, _ := cmd.Flags().GetString("ca-dir")
		if caDir == "" {
			caDir = proxy.DefaultCADir()
		}
		caPath := filepath.Join(caDir, "phoenix-ca.crt")
		proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)

		// Warn (on stderr, so `eval` of stdout is unaffected) when the proxy
		// isn't listening or the CA is missing — otherwise the exports would
		// point the shell at a dead proxy and break all HTTPS.
		if !portOpen(port) {
			fmt.Fprintf(os.Stderr, "[phoenix-firewall] warning: no proxy is listening on 127.0.0.1:%d — start it with 'phoenix-firewall proxy' before using these exports\n", port)
		}
		if _, err := os.Stat(caPath); err != nil {
			fmt.Fprintf(os.Stderr, "[phoenix-firewall] warning: CA certificate not found at %s — run 'phoenix-firewall proxy' or 'phoenix-firewall init' to generate it\n", caPath)
		}

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "export HTTPS_PROXY=%q\n", proxyURL)
		fmt.Fprintf(out, "export HTTP_PROXY=%q\n", proxyURL)
		// CA variables mirror the union set by the package-manager shims
		// (internal/shim: npm/yarn/pnpm -> NODE_EXTRA_CA_CERTS; pip/poetry ->
		// PIP_CERT/REQUESTS_CA_BUNDLE; uv/gem/dotnet/conda -> SSL_CERT_FILE;
		// cargo -> CARGO_HTTP_CAINFO) so every supported PM trusts intercepted TLS.
		fmt.Fprintf(out, "export NODE_EXTRA_CA_CERTS=%q\n", caPath)
		fmt.Fprintf(out, "export PIP_CERT=%q\n", caPath)
		fmt.Fprintf(out, "export REQUESTS_CA_BUNDLE=%q\n", caPath)
		fmt.Fprintf(out, "export SSL_CERT_FILE=%q\n", caPath)
		fmt.Fprintf(out, "export CARGO_HTTP_CAINFO=%q\n", caPath)
		return nil
	},
}

// portOpen reports whether something is listening on 127.0.0.1:port.
func portOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func init() {
	envCmd.Flags().String("ca-dir", "", "Directory holding phoenix-ca.crt (default: ~/.config/phoenix-firewall/)")
	rootCmd.AddCommand(envCmd)
}
