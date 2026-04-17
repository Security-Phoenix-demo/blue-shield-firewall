package registry

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// CustomRegistryConfig defines a custom registry domain to intercept.
// Format: "ecosystem:hostname" (e.g. "npm:packages.example.com")
type CustomRegistryConfig struct {
	Ecosystem string
	Host      string
}

// ParseCustomRegistry parses a "ecosystem:host" string into a CustomRegistryConfig.
// Returns an error if the format is invalid.
func ParseCustomRegistry(s string) (CustomRegistryConfig, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return CustomRegistryConfig{}, fmt.Errorf("invalid custom registry format %q: expected \"ecosystem:host\"", s)
	}
	return CustomRegistryConfig{
		Ecosystem: strings.ToLower(parts[0]),
		Host:      strings.ToLower(parts[1]),
	}, nil
}

// customNameVersionPattern extracts name-version from common archive filenames.
var customNameVersionPattern = regexp.MustCompile(
	`^([A-Za-z0-9@][A-Za-z0-9._/@-]*)-(\d+\.\d+[A-Za-z0-9._-]*)$`,
)

// CustomMatcher matches package downloads from user-configured registry domains.
// It uses heuristic filename parsing since the URL structure is unknown.
type CustomMatcher struct {
	Registries []CustomRegistryConfig
}

// Match checks if the URL targets a configured custom registry and extracts package info.
func (m *CustomMatcher) Match(rawURL string) (*PackageRef, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}

	host := strings.ToLower(u.Host)

	for _, reg := range m.Registries {
		if host != reg.Host {
			continue
		}

		// Extract filename from path
		filename := path.Base(u.Path)
		name, version := extractNameVersion(filename, reg.Ecosystem)
		if name == "" {
			// Fallback: use the last two path segments as name/version
			name, version = extractFromPath(u.Path)
		}
		if name == "" {
			// Last resort: use the path as the package name, no version
			name = strings.Trim(u.Path, "/")
		}

		return &PackageRef{
			Ecosystem: reg.Ecosystem,
			Name:      name,
			Version:   version,
		}, nil
	}

	return nil, nil
}

// extractNameVersion attempts to parse name and version from a filename.
func extractNameVersion(filename, ecosystem string) (string, string) {
	// Strip common archive extensions
	clean := filename
	for _, ext := range []string{".tgz", ".tar.gz", ".whl", ".zip", ".gem", ".jar", ".crate", ".nupkg"} {
		if strings.HasSuffix(strings.ToLower(clean), ext) {
			clean = clean[:len(clean)-len(ext)]
			break
		}
	}

	matches := customNameVersionPattern.FindStringSubmatch(clean)
	if matches == nil {
		return "", ""
	}

	name := matches[1]
	version := matches[2]

	// Normalize PyPI names
	if ecosystem == "pypi" {
		name = strings.ToLower(name)
		name = strings.ReplaceAll(name, "_", "-")
		name = strings.ReplaceAll(name, ".", "-")
	}

	return name, version
}

// extractFromPath tries to pull name and version from URL path segments.
// Looks for patterns like /packages/{name}/{version}/ or /api/v4/.../generic/{name}/{version}/
func extractFromPath(urlPath string) (string, string) {
	segments := strings.Split(strings.Trim(urlPath, "/"), "/")
	if len(segments) < 2 {
		return "", ""
	}
	// Take the last two non-empty segments as name/version
	version := segments[len(segments)-1]
	name := segments[len(segments)-2]

	// Basic version check: must start with a digit
	if len(version) > 0 && version[0] >= '0' && version[0] <= '9' {
		return name, version
	}
	return "", ""
}
