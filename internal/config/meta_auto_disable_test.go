package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetaAutoDisableConfigParse(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantEnabled bool
		wantMax     int
		wantEff     int
	}{
		{"enabled with cap", "routing:\n  meta-auto-disable:\n    enabled: true\n    max-per-hour: 7\n", true, 7, 7},
		{"v8 layout with cap", "config-version: 8\nrouting:\n  meta-auto-disable:\n    enabled: true\n    max-per-hour: 7\n", true, 7, 7},
		{"absent", "routing:\n  strategy: round-robin\n", false, 0, 20},
		{"zero cap falls back", "routing:\n  meta-auto-disable:\n    enabled: true\n    max-per-hour: 0\n", true, 0, 20},
		{"negative cap falls back", "routing:\n  meta-auto-disable:\n    enabled: true\n    max-per-hour: -3\n", true, -3, 20},
	}
	for _, tt := range tests {
		check := func(t *testing.T, cfg *Config) {
			t.Helper()
			got := cfg.Routing.MetaAutoDisable
			if got.Enabled != tt.wantEnabled || got.MaxPerHour != tt.wantMax || got.EffectiveMaxPerHour() != tt.wantEff {
				t.Fatalf("meta-auto-disable = %+v (effective %d), want enabled=%v max=%d effective=%d", got, got.EffectiveMaxPerHour(), tt.wantEnabled, tt.wantMax, tt.wantEff)
			}
		}
		t.Run(tt.name+"/ParseConfigBytes", func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			check(t, cfg)
		})
		t.Run(tt.name+"/LoadConfig", func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(file, []byte(tt.raw), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(file)
			if err != nil {
				t.Fatal(err)
			}
			check(t, cfg)
		})
	}
}

func TestMetaAutoDisableConfigSaveRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("config-version: 8\nrouting:\n  strategy: round-robin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Routing.MetaAutoDisable = MetaAutoDisableConfig{Enabled: true, MaxPerHour: 5}
	if err = SaveConfigPreserveComments(file, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Routing.MetaAutoDisable; !got.Enabled || got.MaxPerHour != 5 {
		t.Fatalf("after save+reload meta-auto-disable = %+v, want enabled=true max-per-hour=5", got)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "meta-auto-disable:") {
		t.Fatalf("saved file lacks routing.meta-auto-disable:\n%s", raw)
	}
}

func TestExampleConfigKeepsMetaAutoDisableOff(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Routing.MetaAutoDisable.Enabled {
		t.Fatalf("config.example.yaml enables meta-auto-disable, want it off")
	}
	if got := cfg.Routing.MetaAutoDisable.EffectiveMaxPerHour(); got != DefaultMetaAutoDisableMaxPerHour {
		t.Fatalf("effective max per hour = %d, want %d", got, DefaultMetaAutoDisableMaxPerHour)
	}
}
