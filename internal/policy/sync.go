// Package policy manages policy download, caching, and staleness detection.
package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Policy holds the active firewall policy downloaded from the backend.
type Policy struct {
	Version   string          `json:"version"`
	Rules     json.RawMessage `json:"rules"`
	FetchedAt time.Time       `json:"-"`
}

// Syncer polls the backend for policy updates on a configurable interval.
type Syncer struct {
	apiURL   string
	apiKey   string
	interval time.Duration
	// staleThreshold is the monotonic-clock ceiling before fail-closed (R-FUNC-073).
	staleThreshold time.Duration

	mu       sync.RWMutex
	policy   *Policy
	lastSync time.Time // monotonic
	stopCh   chan struct{}
}

const defaultInterval = 5 * time.Minute
const defaultStaleThreshold = 24 * time.Hour
const forcedSyncGrace = 23 * time.Hour

func NewSyncer(apiURL, apiKey string) *Syncer {
	return &Syncer{
		apiURL:         apiURL,
		apiKey:         apiKey,
		interval:       defaultInterval,
		staleThreshold: defaultStaleThreshold,
		stopCh:         make(chan struct{}),
	}
}

func (s *Syncer) Start() {
	go s.loop()
}

func (s *Syncer) Stop() {
	close(s.stopCh)
}

func (s *Syncer) loop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	_ = s.fetch()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			_ = s.fetch()
		}
	}
}

// IsStale returns true if policy hasn't been refreshed within the grace period.
// If past the hard threshold, fail-closed is implied by the caller.
func (s *Syncer) IsStale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastSync.IsZero() {
		return true
	}
	return time.Since(s.lastSync) > forcedSyncGrace
}

// IsHardStale returns true after the 24h fail-closed window (R-FUNC-073).
func (s *Syncer) IsHardStale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastSync.IsZero() {
		return true
	}
	return time.Since(s.lastSync) > s.staleThreshold
}

// Current returns the active policy (nil if none loaded).
func (s *Syncer) Current() *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

func (s *Syncer) fetch() error {
	req, err := http.NewRequest(http.MethodGet, s.apiURL+"/api/v1/firewall/agent/config", nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", s.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("policy fetch: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var p Policy
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("policy parse: %w", err)
	}
	p.FetchedAt = time.Now()
	s.mu.Lock()
	s.policy = &p
	s.lastSync = time.Now()
	s.mu.Unlock()
	return nil
}
