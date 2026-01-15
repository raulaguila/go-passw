package config

import (
	"os"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	// Use the policy.yaml from parent directory
	cfg, err := Load("../policy.yaml")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Policies == nil {
		t.Fatal("expected policies, got nil")
	}

	if cfg.Policies.Length == nil || !cfg.Policies.Length.Enabled {
		t.Error("expected length policy to be enabled")
	}

	if cfg.Policies.Length.Min != 8 {
		t.Errorf("expected min length 8, got %d", cfg.Policies.Length.Min)
	}
}

func TestLoadInvalidPath(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	// Create temp file with invalid YAML
	tmpfile, err := os.CreateTemp("", "invalid*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	tmpfile.WriteString("invalid: yaml: content: [")
	tmpfile.Close()

	_, err = Load(tmpfile.Name())
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "nil policies",
			cfg:     &Config{},
			wantErr: true,
		},
		{
			name: "negative min length",
			cfg: &Config{
				Policies: &Policies{
					Length: &LengthConfig{Enabled: true, Min: -1, Max: 10},
				},
			},
			wantErr: true,
		},
		{
			name: "max less than min",
			cfg: &Config{
				Policies: &Policies{
					Length: &LengthConfig{Enabled: true, Min: 10, Max: 5},
				},
			},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: &Config{
				Policies: &Policies{
					Length: &LengthConfig{Enabled: true, Min: 8, Max: 128},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
