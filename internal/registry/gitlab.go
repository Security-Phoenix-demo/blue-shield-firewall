package registry

import (
	"net/url"
	"regexp"
	"strings"
)

// GitLab Package Registry URL patterns:
//
// npm:   https://gitlab.com/api/v4/projects/12345/packages/npm/@scope/name/-/@scope/name-1.0.0.tgz
// pypi:  https://gitlab.com/api/v4/projects/12345/packages/pypi/files/abc123/requests-2.31.0.tar.gz
// maven: https://gitlab.com/api/v4/projects/12345/packages/maven/com/example/lib/1.0/lib-1.0.jar
// go:    https://gitlab.com/api/v4/projects/12345/packages/go/example.com/mod/@v/v1.0.0.zip
// generic: https://gitlab.com/api/v4/projects/12345/packages/generic/mylib/1.0.0/mylib-1.0.0.tar.gz
//
// Self-hosted: same paths under https://gitlab.example.com/api/v4/projects/...

// gitlabNpmPattern matches GitLab npm package downloads.
// Scoped:   /api/v4/projects/123/packages/npm/@scope/name/-/@scope/name-1.0.0.tgz
// Unscoped: /api/v4/projects/123/packages/npm/lodash/-/lodash-4.17.21.tgz
// The name group captures everything between /npm/ and /-/.
// The version is extracted from the filename after the last hyphen before .tgz.
var gitlabNpmPattern = regexp.MustCompile(
	`/api/v4/projects/\d+/packages/npm/((?:@[^/]+/)?[^/]+)/-/.*-(\d+\.\d+\.\d+[^.]*)\.tgz$`,
)

// gitlabPypiPattern matches GitLab PyPI package downloads.
var gitlabPypiPattern = regexp.MustCompile(
	`/api/v4/projects/\d+/packages/pypi/files/[^/]+/([A-Za-z0-9][A-Za-z0-9._-]*)-(\d+\.\d+[^/]*)\.(?:tar\.gz|whl|zip)$`,
)

// gitlabMavenPattern matches GitLab Maven package downloads.
var gitlabMavenPattern = regexp.MustCompile(
	`/api/v4/projects/\d+/packages/maven/(.+)/([^/]+)/([^/]+)/[^/]+\.[a-z]+$`,
)

// gitlabGenericPattern matches GitLab generic package downloads.
var gitlabGenericPattern = regexp.MustCompile(
	`/api/v4/projects/\d+/packages/generic/([^/]+)/([^/]+)/`,
)

// GitLabMatcher identifies GitLab package registry downloads.
// It matches both gitlab.com and self-hosted GitLab instances.
type GitLabMatcher struct {
	// Hosts is the set of GitLab hostnames to match.
	// If empty, defaults to gitlab.com only.
	Hosts []string
}

// Match checks if the URL is a GitLab package registry download and extracts package info.
func (m *GitLabMatcher) Match(rawURL string) (*PackageRef, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}

	if !m.isGitLabHost(u.Host) {
		return nil, nil
	}

	path := u.Path

	// Try npm pattern
	if matches := gitlabNpmPattern.FindStringSubmatch(path); matches != nil {
		name := strings.ReplaceAll(matches[1], "%40", "@")
		return &PackageRef{
			Ecosystem: "npm",
			Name:      name,
			Version:   matches[2],
		}, nil
	}

	// Try PyPI pattern
	if matches := gitlabPypiPattern.FindStringSubmatch(path); matches != nil {
		return &PackageRef{
			Ecosystem: "pypi",
			Name:      normalizePypiName(matches[1]),
			Version:   matches[2],
		}, nil
	}

	// Try Maven pattern
	if matches := gitlabMavenPattern.FindStringSubmatch(path); matches != nil {
		groupPath := matches[1]
		artifact := matches[2]
		version := matches[3]
		groupID := strings.ReplaceAll(groupPath, "/", ".")
		return &PackageRef{
			Ecosystem: "maven",
			Name:      groupID + ":" + artifact,
			Version:   version,
		}, nil
	}

	// Try generic pattern
	if matches := gitlabGenericPattern.FindStringSubmatch(path); matches != nil {
		return &PackageRef{
			Ecosystem: "generic",
			Name:      matches[1],
			Version:   matches[2],
		}, nil
	}

	return nil, nil
}

// isGitLabHost checks if the given hostname is a known GitLab instance.
func (m *GitLabMatcher) isGitLabHost(host string) bool {
	hosts := m.Hosts
	if len(hosts) == 0 {
		hosts = []string{"gitlab.com"}
	}
	for _, h := range hosts {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}
