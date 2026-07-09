package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type PackageInventoryItem struct {
	Ecosystem      string                 `json:"ecosystem"`
	PackageName    string                 `json:"package_name"`
	PackageVersion string                 `json:"package_version,omitempty"`
	NormalizedPURL string                 `json:"normalized_purl,omitempty"`
	InstallScope   string                 `json:"install_scope,omitempty"`
	InstallSource  string                 `json:"install_source,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type SoftwareInventoryItem struct {
	SoftwareKind  string                 `json:"software_kind"`
	Name          string                 `json:"name"`
	Version       string                 `json:"version,omitempty"`
	Path          string                 `json:"path,omitempty"`
	InstallSource string                 `json:"install_source,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type SkillInventoryItem struct {
	TargetKind    string                 `json:"target_kind"`
	Platform      string                 `json:"platform,omitempty"`
	Name          string                 `json:"name"`
	Version       string                 `json:"version,omitempty"`
	InstallSource string                 `json:"install_source,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type CombinedInventoryPayload struct {
	DeviceID      string                  `json:"device_id"`
	CollectorType string                  `json:"collector_type"`
	CollectedAt   string                  `json:"collected_at,omitempty"`
	Packages      []PackageInventoryItem  `json:"packages,omitempty"`
	Skills        []SkillInventoryItem    `json:"skills,omitempty"`
	Software      []SoftwareInventoryItem `json:"software,omitempty"`
}

type EnrollRequest struct {
	TenantID         string                 `json:"tenant_id,omitempty"`
	DeviceID         string                 `json:"device_id"`
	BootstrapToken   string                 `json:"bootstrap_token,omitempty"`
	Hostname         string                 `json:"hostname"`
	Platform         string                 `json:"platform"`
	AgentVersion     string                 `json:"agent_version"`
	TeamID           string                 `json:"team_id,omitempty"`
	AssignedUserHash string                 `json:"assigned_user_hash,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type EnrollResponse struct {
	APIKey        string `json:"api_key"`
	APIKeyID      string `json:"api_key_id"`
	DeviceID      string `json:"device_id"`
	PolicyVersion string `json:"policy_version,omitempty"`
}

type EndpointActivityEvent struct {
	DeviceID        string                 `json:"device_id"`
	EventType       string                 `json:"event_type"`
	CollectorType   string                 `json:"collector_type,omitempty"`
	SourceEventKey  string                 `json:"source_event_key,omitempty"`
	OccurredAt      string                 `json:"occurred_at,omitempty"`
	Ecosystem       string                 `json:"ecosystem,omitempty"`
	PackageName     string                 `json:"package_name,omitempty"`
	PackageVersion  string                 `json:"package_version,omitempty"`
	TargetKind      string                 `json:"target_kind,omitempty"`
	SoftwareName    string                 `json:"software_name,omitempty"`
	SoftwareVersion string                 `json:"software_version,omitempty"`
	CommandText     string                 `json:"command_text,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

func (c *Client) UploadCombinedInventory(payload CombinedInventoryPayload) error {
	return c.postAgentJSON("/api/v1/firewall/agent/inventory/combined", payload)
}

func (c *Client) EnrollDevice(payload EnrollRequest) (*EnrollResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/firewall/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("x-api-key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("firewall API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("firewall API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var out EnrollResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse enrollment response: %w", err)
	}
	return &out, nil
}

func (c *Client) SendActivity(event EndpointActivityEvent) error {
	return c.postAgentJSON("/api/v1/firewall/agent/activity", event)
}

func (c *Client) postAgentJSON(path string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("x-api-key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("firewall API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("firewall API returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
