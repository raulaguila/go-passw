package validator

// PolicyConfig represents the YAML structure
type PolicyConfig struct {
	Policies *Policies `yaml:"policies"`
	Hashing  *Hashing  `yaml:"hashing"`
}

// ================================
// Policies Config
// ================================

type Policies struct {
	Length   *LengthConfig   `yaml:"length"`
	Entropy  *EntropyConfig  `yaml:"entropy"`
	Sequence *SequenceConfig `yaml:"sequence"`
	Category *CategoryConfig `yaml:"category"`
}

type LengthConfig struct {
	Enabled bool `yaml:"enabled"`
	Min     int  `yaml:"min"`
	Max     int  `yaml:"max"`
}

type EntropyConfig struct {
	Enabled        bool     `yaml:"enabled"`
	MinEntropy     float64  `yaml:"min_entropy"`
	Blacklist      []string `yaml:"blacklist"`
	BlacklistBoost float64  `yaml:"blacklist_boost"`
}

type SequenceConfig struct {
	Enabled     bool `yaml:"enabled"`
	MaxSequence int  `yaml:"max_sequence"`
}

type CategoryConfig struct {
	Enabled bool                 `yaml:"enabled"`
	Rules   []CategoryRuleConfig `yaml:"rules"`
}

type CategoryRuleConfig struct {
	Name      string `yaml:"name"`
	Enabled   bool   `yaml:"enabled"`
	Min       int    `yaml:"min"`
	Predicate string `yaml:"predicate"`
}

// ================================
// Hashing Config
// ================================

type Hashing struct {
	Algorithm string        `yaml:"algorithm"`
	Bcrypt    *BcryptConfig `yaml:"bcrypt"`
	Argon2    *Argon2Config `yaml:"argon2"`
}

type BcryptConfig struct {
	Cost int `yaml:"cost"`
}

type Argon2Config struct {
	Time    uint32 `yaml:"time"`
	Memory  uint32 `yaml:"memory"`
	Threads uint8  `yaml:"cost"`
	KeyLen  uint32 `yaml:"keyLen"`
}
