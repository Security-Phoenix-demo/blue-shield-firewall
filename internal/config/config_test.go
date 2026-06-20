package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestLoad_FailModeFromViper(t *testing.T) {
	viper.Reset()
	viper.Set("fail_mode.mode", "closed")
	defer viper.Reset()

	cfg := Load()
	if cfg.FailMode != "closed" {
		t.Errorf("FailMode = %q, want closed", cfg.FailMode)
	}
}

func TestLoad_FailModeDefaultsEmptyToOpen(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	cfg := Load()
	if cfg.FailMode != "open" {
		t.Errorf("FailMode = %q, want open (default)", cfg.FailMode)
	}
}
