// Package config defines configuration types for the password validation library.
package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the complete policy configuration.
type Config struct {
	// Policies contains the password validation rules.
	Policies *Policies `yaml:"policies"`

	// Hashing contains password hashing configuration.
	// Reserved for future use.
	Hashing *Hashing `yaml:"hashing"`
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Policies == nil {
		return errors.New("policies section is required")
	}
	return c.Policies.Validate()
}

// Policies contains all password policy configurations.
type Policies struct {
	Length   *LengthConfig   `yaml:"length"`
	Entropy  *EntropyConfig  `yaml:"entropy"`
	Sequence *SequenceConfig `yaml:"sequence"`
	Category *CategoryConfig `yaml:"category"`
}

// Validate checks the policies configuration for errors.
func (p *Policies) Validate() error {
	if p.Length != nil && p.Length.Enabled {
		if p.Length.Min < 0 {
			return fmt.Errorf("length.min must be non-negative, got %d", p.Length.Min)
		}
		if p.Length.Max > 0 && p.Length.Max < p.Length.Min {
			return fmt.Errorf("length.max (%d) must be >= length.min (%d)", p.Length.Max, p.Length.Min)
		}
	}

	if p.Entropy != nil && p.Entropy.Enabled {
		if p.Entropy.MinEntropy < 0 {
			return fmt.Errorf("entropy.min_entropy must be non-negative, got %f", p.Entropy.MinEntropy)
		}
	}

	if p.Sequence != nil && p.Sequence.Enabled {
		if p.Sequence.MaxSequence < 1 {
			return fmt.Errorf("sequence.max_sequence must be >= 1, got %d", p.Sequence.MaxSequence)
		}
	}

	return nil
}

// LengthConfig configures the password length rule.
type LengthConfig struct {
	Enabled bool `yaml:"enabled"`
	Min     int  `yaml:"min"`
	Max     int  `yaml:"max"`
}

// EntropyConfig configures the password entropy rule.
type EntropyConfig struct {
	Enabled        bool     `yaml:"enabled"`
	MinEntropy     float64  `yaml:"min_entropy"`
	Blacklist      []string `yaml:"blacklist"`
	BlacklistBoost float64  `yaml:"blacklist_boost"`
}

// SequenceConfig configures the sequence detection rule.
type SequenceConfig struct {
	Enabled         bool `yaml:"enabled"`
	MaxSequence     int  `yaml:"max_sequence"`
	IncludeKeyboard bool `yaml:"include_keyboard"` // Detect keyboard patterns like qwerty
}

// CategoryConfig configures character category requirements.
type CategoryConfig struct {
	Enabled bool                 `yaml:"enabled"`
	Rules   []CategoryRuleConfig `yaml:"rules"`
}

// CategoryRuleConfig defines a single category requirement.
type CategoryRuleConfig struct {
	Name      string `yaml:"name"`
	Enabled   bool   `yaml:"enabled"`
	Min       int    `yaml:"min"`
	Predicate string `yaml:"predicate"`
}

// Hashing contains password hashing configuration.
// Reserved for future use.
type Hashing struct {
	Algorithm string        `yaml:"algorithm"`
	Bcrypt    *BcryptConfig `yaml:"bcrypt"`
	Argon2    *Argon2Config `yaml:"argon2"`
}

// BcryptConfig contains bcrypt hashing parameters.
type BcryptConfig struct {
	Cost int `yaml:"cost"`
}

// Argon2Config contains argon2 hashing parameters.
type Argon2Config struct {
	Time    uint32 `yaml:"time"`
	Memory  uint32 `yaml:"memory"`
	Threads uint8  `yaml:"threads"` // Fixed: was "cost" in legacy
	KeyLen  uint32 `yaml:"keyLen"`
}

// Load reads and parses a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}
