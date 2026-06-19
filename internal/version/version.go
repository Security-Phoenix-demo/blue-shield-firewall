// Package version is the single source of truth for the agent version string.
package version

// Agent is the phoenix-firewall agent version. Overridden by goreleaser ldflags
// on release builds via cmd.version; this constant is the library default.
const Agent = "0.1.0"
