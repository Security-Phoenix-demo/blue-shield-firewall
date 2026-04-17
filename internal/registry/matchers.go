package registry

import "log"

// CompositeMatchers tries multiple RegistryMatcher implementations in order.
type CompositeMatchers struct {
	matchers []RegistryMatcher
}

// NewCompositeMatchers creates a CompositeMatchers with all built-in registry matchers
// (npm, PyPI, Cargo, Gem, Maven). For GitLab and custom registries, use
// NewCompositeMatchersWithConfig.
func NewCompositeMatchers() *CompositeMatchers {
	return &CompositeMatchers{
		matchers: []RegistryMatcher{
			&NpmMatcher{},
			&PypiMatcher{},
			&CargoMatcher{},
			&GemMatcher{},
			&MavenMatcher{},
		},
	}
}

// MatcherConfig holds configuration for building registry matchers.
type MatcherConfig struct {
	// GitLabHosts is a list of GitLab instance hostnames to intercept.
	// gitlab.com is always included automatically.
	GitLabHosts []string
	// ExtraRegistries is a list of "ecosystem:hostname" entries for custom registries.
	ExtraRegistries []string
}

// NewCompositeMatchersWithConfig creates a CompositeMatchers with built-in matchers
// plus GitLab and custom registry matchers based on configuration.
func NewCompositeMatchersWithConfig(cfg MatcherConfig) *CompositeMatchers {
	matchers := []RegistryMatcher{
		&NpmMatcher{},
		&PypiMatcher{},
		&CargoMatcher{},
		&GemMatcher{},
		&MavenMatcher{},
	}

	// Add GitLab matcher if any hosts are configured (or always for gitlab.com)
	gitlabHosts := []string{"gitlab.com"}
	for _, h := range cfg.GitLabHosts {
		if h != "" && h != "gitlab.com" {
			gitlabHosts = append(gitlabHosts, h)
		}
	}
	if len(cfg.GitLabHosts) > 0 || len(cfg.ExtraRegistries) > 0 {
		matchers = append(matchers, &GitLabMatcher{Hosts: gitlabHosts})
	}

	// Add custom registries
	if len(cfg.ExtraRegistries) > 0 {
		var customRegs []CustomRegistryConfig
		for _, entry := range cfg.ExtraRegistries {
			reg, err := ParseCustomRegistry(entry)
			if err != nil {
				log.Printf("[registry] skipping invalid custom registry %q: %v", entry, err)
				continue
			}
			customRegs = append(customRegs, reg)
		}
		if len(customRegs) > 0 {
			matchers = append(matchers, &CustomMatcher{Registries: customRegs})
		}
	}

	return &CompositeMatchers{matchers: matchers}
}

// Match tries each registered matcher in order and returns the first match.
func (c *CompositeMatchers) Match(url string) (*PackageRef, error) {
	for _, m := range c.matchers {
		ref, err := m.Match(url)
		if err != nil {
			return nil, err
		}
		if ref != nil {
			return ref, nil
		}
	}
	return nil, nil
}
