package proxy_test

import "github.com/Security-Phoenix-demo/phoenix-firewall/internal/client"

// newTestClient creates a firewall client pointing at a test server URL.
func newTestClient(baseURL, apiKey string) *client.Client {
	return client.New(baseURL, apiKey)
}
