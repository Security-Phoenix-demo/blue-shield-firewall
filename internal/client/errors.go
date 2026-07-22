package client

import (
	"fmt"
	"net/http"
)

// APIError is returned when the firewall API responds with a non-2xx status.
// It lets callers distinguish a definitive auth rejection (invalid, expired, or
// wrong-scope key -> 401/403) from other failures. Transport failures (backend
// unreachable) surface as plain errors, not *APIError.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("firewall API returned %d: %s", e.StatusCode, e.Body)
	}
	return fmt.Sprintf("firewall API returned %d", e.StatusCode)
}

// IsAuth reports whether the failure was an authentication/authorization
// rejection rather than a transient/server-side error.
func (e *APIError) IsAuth() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}
