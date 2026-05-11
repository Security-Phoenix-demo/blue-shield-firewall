package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Run as a managed system service (endpoint mode)",
	Long: `Starts the phoenix-firewall in endpoint mode:
- Supervisor process (privileged): manages worker lifecycle, shim installation, MDM compliance writing
- Worker process (unprivileged _phoenixfirewall user): policy evaluation, IPC socket listener

Use 'phoenix-firewall system install' to install the OS service.
Use 'phoenix-firewall system start|stop|status' to manage it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSystemMode()
	},
}

var systemInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install phoenix-firewall as an OS service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return installService()
	},
}

var systemUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the phoenix-firewall OS service",
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
	fmt.Fprintln(os.Stdout, "[phoenix-firewall] starting system mode (supervisor)")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	fmt.Fprintln(os.Stdout, "[phoenix-firewall] shutting down")
	return nil
}

func installService() error {
	fmt.Fprintln(os.Stdout, "[phoenix-firewall] installing OS service (not yet implemented — see internal/service/)")
	return nil
}

func uninstallService() error {
	fmt.Fprintln(os.Stdout, "[phoenix-firewall] uninstalling OS service (not yet implemented — see internal/service/)")
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
