package inventory

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/client"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/registry"
)

type MetadataHints struct {
	TeamID    string
	ProjectID string
}

func PackageItems(refs []registry.PackageRef, installSource string, hints MetadataHints) []client.PackageInventoryItem {
	items := make([]client.PackageInventoryItem, 0, len(refs))
	for _, ref := range refs {
		metadata := hintMetadata(hints)
		items = append(items, client.PackageInventoryItem{
			Ecosystem:      ref.Ecosystem,
			PackageName:    ref.Name,
			PackageVersion: ref.Version,
			NormalizedPURL: normalizedPURL(ref),
			InstallScope:   "project",
			InstallSource:  installSource,
			Metadata:       metadata,
		})
	}
	return items
}

func DeveloperSoftware(hints MetadataHints) []client.SoftwareInventoryItem {
	candidates := []struct {
		kind string
		name string
		args []string
	}{
		{"phoenix_component", "phoenix-firewall", []string{"--version"}},
		{"package_manager", "npm", []string{"--version"}},
		{"package_manager", "pnpm", []string{"--version"}},
		{"package_manager", "yarn", []string{"--version"}},
		{"package_manager", "bun", []string{"--version"}},
		{"package_manager", "pip", []string{"--version"}},
		{"package_manager", "pip3", []string{"--version"}},
		{"package_manager", "uv", []string{"--version"}},
		{"package_manager", "poetry", []string{"--version"}},
		{"package_manager", "cargo", []string{"--version"}},
		{"package_manager", "gem", []string{"--version"}},
		{"package_manager", "go", []string{"version"}},
		{"coding_agent", "claude", []string{"--version"}},
		{"coding_agent", "codex", []string{"--version"}},
		{"coding_agent", "cursor", []string{"--version"}},
	}

	items := make([]client.SoftwareInventoryItem, 0, len(candidates))
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate.name)
		if err != nil {
			continue
		}
		items = append(items, client.SoftwareInventoryItem{
			SoftwareKind:  candidate.kind,
			Name:          candidate.name,
			Version:       detectVersion(path, candidate.args),
			Path:          path,
			InstallSource: "path",
			Metadata:      hintMetadata(hints),
		})
	}
	return items
}

func hintMetadata(hints MetadataHints) map[string]interface{} {
	metadata := map[string]interface{}{}
	if hints.TeamID != "" {
		metadata["team_id_hint"] = hints.TeamID
	}
	if hints.ProjectID != "" {
		metadata["project_id_hint"] = hints.ProjectID
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

func normalizedPURL(ref registry.PackageRef) string {
	ecosystem := ref.Ecosystem
	if ecosystem == "crates" {
		ecosystem = "cargo"
	}
	if ref.Version == "" {
		return "pkg:" + ecosystem + "/" + ref.Name
	}
	return "pkg:" + ecosystem + "/" + ref.Name + "@" + ref.Version
}

func detectVersion(path string, args []string) string {
	if len(args) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}
