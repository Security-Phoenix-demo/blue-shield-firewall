// Package bypass validates single-invocation bypass tokens (JWT, KMS-signed).
package bypass

import (
	"errors"
	"os"
	"sync"
	"time"
)

// ErrTokenInvalid is returned when the bypass token fails validation.
var ErrTokenInvalid = errors.New("bypass token invalid or expired")

// ErrTokenReplayed is returned when the jti has already been used.
var ErrTokenReplayed = errors.New("bypass token jti already consumed")

// Validator verifies bypass tokens from PHOENIX_BYPASS_TOKEN env var.
// Per R-FUNC-067, the token lifetime is single-invocation (jti consumed on first use).
type Validator struct {
	mu      sync.Mutex
	usedJTI map[string]time.Time
}

func New() *Validator {
	return &Validator{usedJTI: make(map[string]time.Time)}
}

// Check validates the token from the env var. Returns nil if allowed.
func (v *Validator) Check() error {
	token := os.Getenv("PHOENIX_BYPASS_TOKEN")
	if token == "" {
		return nil // no bypass token set — normal evaluation path
	}
	// TODO(B5): parse JWT, verify signature against KMS public key,
	// check expiry, check jti replay cache.
	// Stub: accept any non-empty token for scaffolding.
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, used := v.usedJTI[token]; used {
		return ErrTokenReplayed
	}
	v.usedJTI[token] = time.Now()
	return nil
}
