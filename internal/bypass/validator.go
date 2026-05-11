// Package bypass validates single-invocation bypass tokens (ED25519-signed JWT).
package bypass

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrTokenInvalid = errors.New("bypass token invalid or expired")
var ErrTokenReplayed = errors.New("bypass token jti already consumed")

type Validator struct {
	mu      sync.Mutex
	usedJTI map[string]time.Time
	pubKey  ed25519.PublicKey
}

// New loads the public key from cfgDir (defaults to ~/.config/phoenix-firewall/).
func New(cfgDir string) *Validator {
	if cfgDir == "" {
		home, _ := os.UserHomeDir()
		cfgDir = filepath.Join(home, ".config", "phoenix-firewall")
	}
	v := &Validator{usedJTI: make(map[string]time.Time)}
	pubPath := filepath.Join(cfgDir, pubKeyFileName)
	if data, err := os.ReadFile(pubPath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				if ed, ok := pub.(ed25519.PublicKey); ok {
					v.pubKey = ed
				}
			}
		}
	}
	return v
}

// Check validates the bypass token. Returns nil if no token is set (allow) or token is valid.
func (v *Validator) Check() error {
	token := os.Getenv("PHOENIX_BYPASS_TOKEN")
	if token == "" {
		return nil
	}
	claims, err := v.verifyJWT(token)
	if err != nil {
		return ErrTokenInvalid
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return ErrTokenInvalid
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return ErrTokenInvalid
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, used := v.usedJTI[jti]; used {
		return ErrTokenReplayed
	}
	v.usedJTI[jti] = time.Now()
	return nil
}

func (v *Validator) verifyJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	if v.pubKey != nil {
		msg := parts[0] + "." + parts[1]
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("decode sig: %w", err)
		}
		if !ed25519.Verify(v.pubKey, []byte(msg), sig) {
			return nil, fmt.Errorf("invalid signature")
		}
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	return claims, nil
}
