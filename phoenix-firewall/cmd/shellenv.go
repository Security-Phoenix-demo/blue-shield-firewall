package cmd

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/config"
	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/proxy"
	"github.com/spf13/cobra"
)

var envCmd = &cobra.Command{
	Use:     "env",
	Aliases: []string{"shellenv"},
	Short:   "Print shell exports that route package managers through the proxy",
	Long: `Print environment-variable export statements that route HTTP(S) traffic and
TLS trust through the Phoenix firewall proxy, so package managers (npm, pip,
cargo, git) honour it. Designed to be eval'd into the current shell:

  eval "$(phoenix-firewall env)"                       # bash / zsh
  phoenix-firewall env --shell fish | source           # fish
  phoenix-firewall env --shell powershell | Invoke-Expression

The proxy URL is derived from --port (default 8080) and the CA path from
--ca-dir (default ~/.phoenix-firewall/ca/). Use --unset to remove the variables
again. This command only prints — start the proxy itself with 'proxy'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()
		caDir, _ := cmd.Flags().GetString("ca-dir")
		if caDir == "" {
			caDir = proxy.DefaultCADir()
		}
		shell, _ := cmd.Flags().GetString("shell")
		unset, _ := cmd.Flags().GetBool("unset")
		return printProxyExports(cmd.OutOrStdout(), cfg, caDir, shell, unset)
	},
}

func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.Flags().String("ca-dir", "", "Directory holding the CA certificate (default: ~/.phoenix-firewall/ca/)")
	envCmd.Flags().String("shell", "posix", "Output syntax: posix|bash|zsh|sh|fish|powershell|pwsh")
	envCmd.Flags().Bool("unset", false, "Print statements that unset the proxy variables instead of setting them")
}

// proxyEnvVars returns the ordered (name, value) pairs that point common package
// managers and HTTP clients at the running proxy and its CA certificate.
func proxyEnvVars(cfg *config.Config, caDir string) [][2]string {
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.Port)
	caCert := filepath.Join(caDir, "phoenix-ca.crt")
	return [][2]string{
		{"HTTP_PROXY", proxyURL},
		{"HTTPS_PROXY", proxyURL},
		{"http_proxy", proxyURL},
		{"https_proxy", proxyURL},
		{"NODE_EXTRA_CA_CERTS", caCert}, // npm / node
		{"REQUESTS_CA_BUNDLE", caCert},  // pip / requests
		{"PIP_CERT", caCert},            // pip
		{"CARGO_HTTP_CAINFO", caCert},   // cargo
		{"GIT_SSL_CAINFO", caCert},      // git
		{"SSL_CERT_FILE", caCert},       // curl / openssl-based clients
	}
}

// printProxyExports writes shell-specific set/unset statements for the proxy env.
func printProxyExports(w io.Writer, cfg *config.Config, caDir, shell string, unset bool) error {
	// Resolve to an absolute path so the emitted CA-cert variables stay valid even
	// if the caller (or a subprocess like a package install) later changes cwd.
	absCADir, err := filepath.Abs(caDir)
	if err != nil {
		return fmt.Errorf("resolve absolute CA directory %q: %w", caDir, err)
	}
	caDir = absCADir

	// Validate the shell up front rather than silently emitting POSIX syntax for an
	// unsupported value, which would produce statements the target shell can't eval.
	switch shell {
	case "posix", "bash", "zsh", "sh", "fish", "powershell", "pwsh":
	default:
		return fmt.Errorf("unsupported shell %q (supported: posix, bash, zsh, sh, fish, powershell, pwsh)", shell)
	}

	for _, kv := range proxyEnvVars(cfg, caDir) {
		name, val := kv[0], kv[1]
		switch shell {
		case "fish":
			if unset {
				fmt.Fprintf(w, "set -e %s\n", name)
			} else {
				fmt.Fprintf(w, "set -gx %s %q\n", name, val)
			}
		case "powershell", "pwsh":
			if unset {
				fmt.Fprintf(w, "Remove-Item Env:%s -ErrorAction SilentlyContinue\n", name)
			} else {
				// Single-quoted PowerShell strings are literal: no $ interpolation and
				// no backslash escaping, so Windows CA paths (C:\...) survive intact.
				fmt.Fprintf(w, "$Env:%s = %s\n", name, psSingleQuote(val))
			}
		default: // posix: bash / zsh / sh
			if unset {
				fmt.Fprintf(w, "unset %s\n", name)
			} else {
				fmt.Fprintf(w, "export %s=%q\n", name, val)
			}
		}
	}
	return nil
}

// psSingleQuote wraps s in PowerShell single quotes, escaping any embedded single
// quote by doubling it (”) per PowerShell literal-string rules.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
