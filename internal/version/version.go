// Package version is the single source of truth for the agent version string.
package version

// Agent is the phoenix-firewall agent version reported in telemetry heartbeats.
// Release builds (goreleaser) and `make build` both override it via
// -X .../internal/version.Agent=<version>; this constant is the dev-build default.
var Agent = "dev"
