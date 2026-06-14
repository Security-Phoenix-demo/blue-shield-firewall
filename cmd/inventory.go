package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/client"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/config"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/inventory"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/registry"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Collect and upload endpoint inventory",
	Long:  `Collect package lockfile inventory and developer-tooling software inventory, then upload it to the Phoenix collector endpoint.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		warnIfAPIKeyFlag(cmd)
		cfg := config.Load()
		deviceID, _ := cmd.Flags().GetString("device-id")
		if deviceID == "" {
			deviceID = cfg.DeviceID
		}
		teamID, _ := cmd.Flags().GetString("team-id")
		if teamID == "" {
			teamID = cfg.TeamID
		}
		projectID, _ := cmd.Flags().GetString("project-id")
		lockfileFlags, _ := cmd.Flags().GetStringSlice("lockfile")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		if deviceID == "" {
			return fmt.Errorf("--device-id or PHOENIX_DEVICE_ID is required")
		}

		refs, sources, err := collectLockfileRefs(lockfileFlags)
		if err != nil {
			return err
		}
		hints := inventory.MetadataHints{TeamID: teamID, ProjectID: projectID}
		packages := []client.PackageInventoryItem{}
		for _, source := range sources {
			packages = append(packages, inventory.PackageItems(refs[source], source, hints)...)
		}

		payload := client.CombinedInventoryPayload{
			DeviceID:      deviceID,
			CollectorType: "shim",
			CollectedAt:   time.Now().UTC().Format(time.RFC3339),
			Packages:      packages,
			Software:      inventory.DeveloperSoftware(hints),
		}

		if dryRun {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(payload)
		}

		if cfg.APIKey == "" {
			return fmt.Errorf("--api-key or PHOENIX_API_KEY is required to upload inventory")
		}
		if err := client.New(cfg.APIUrl, cfg.APIKey).UploadCombinedInventory(payload); err != nil {
			return err
		}
		fmt.Printf("[phoenix-firewall] uploaded inventory: %d packages, %d software items\n", len(payload.Packages), len(payload.Software))
		return nil
	},
}

func collectLockfileRefs(paths []string) (map[string][]registry.PackageRef, []string, error) {
	if len(paths) == 0 {
		paths = defaultLockfiles()
	}
	refsBySource := map[string][]registry.PackageRef{}
	sources := []string{}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, fmt.Errorf("stat %s: %w", path, err)
		}
		refs, err := parseLockfile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if len(refs) == 0 {
			continue
		}
		source := filepath.ToSlash(path)
		refsBySource[source] = refs
		sources = append(sources, source)
	}
	return refsBySource, sources, nil
}

func defaultLockfiles() []string {
	return []string{"package-lock.json", "requirements.txt", "Cargo.lock"}
}

func init() {
	inventoryCmd.Flags().String("device-id", "", "Endpoint device UUID (or PHOENIX_DEVICE_ID)")
	inventoryCmd.Flags().String("team-id", "", "Optional team hint stored as collector metadata only")
	inventoryCmd.Flags().String("project-id", "", "Optional project/repository hint stored as collector metadata only")
	inventoryCmd.Flags().StringSlice("lockfile", nil, "Lockfile to include (repeatable; default: package-lock.json, requirements.txt, Cargo.lock if present)")
	inventoryCmd.Flags().Bool("dry-run", false, "Print inventory payload instead of uploading")
	_ = viper.BindPFlag("device_id", inventoryCmd.Flags().Lookup("device-id"))
	_ = viper.BindPFlag("team_id", inventoryCmd.Flags().Lookup("team-id"))
	rootCmd.AddCommand(inventoryCmd)
}
