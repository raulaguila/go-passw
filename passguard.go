package passguard

import (
	"context"
	"log/slog"

	"github.com/raulaguila/passguard/config"
	"github.com/raulaguila/passguard/engine"
	"github.com/raulaguila/passguard/errors"
)

// ValidationError is an alias for errors.ValidationError for convenience.
type ValidationError = errors.ValidationError

// Result contains detailed validation results including score and strength.
type Result struct {
	// Valid indicates whether the password passed all validation rules.
	Valid bool `json:"valid"`

	// Score is a 0-100 score representing password strength.
	Score int `json:"score"`

	// Strength is a human-readable strength label.
	Strength string `json:"strength"`

	// Entropy is the calculated password entropy in bits.
	Entropy float64 `json:"entropy"`

	// Errors contains all validation failures.
	Errors []ValidationError `json:"errors,omitempty"`

	// Suggestions contains tips to improve the password.
	Suggestions []string `json:"suggestions,omitempty"`
}

// Validator provides password validation against configured policies.
type Validator struct {
	engine     *engine.Engine
	reloadable *engine.ReloadableEngine
	opts       *options
}

// Option configures a Validator.
type Option func(*options)

type options struct {
	autoReload bool
	failFast   bool
	logger     *slog.Logger
}

// WithAutoReload enables automatic policy reloading when the config file changes.
func WithAutoReload() Option {
	return func(o *options) {
		o.autoReload = true
	}
}

// WithFailFast stops validation at the first error instead of collecting all errors.
// This can improve performance when you only need to know if a password is valid.
func WithFailFast() Option {
	return func(o *options) {
		o.failFast = true
	}
}

// WithLogger sets a custom logger for the validator.
// Pass nil to disable logging entirely.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		o.logger = logger
	}
}

// New creates a new password validator from a YAML configuration file.
func New(configPath string) (*Validator, error) {
	return NewWithOptions(configPath)
}

// NewWithOptions creates a new password validator with custom options.
func NewWithOptions(configPath string, opts ...Option) (*Validator, error) {
	o := &options{
		logger: slog.Default(), // Default logger
	}
	for _, opt := range opts {
		opt(o)
	}

	if o.autoReload {
		reloadable, err := engine.NewReloadableWithLogger(configPath, o.logger)
		if err != nil {
			return nil, err
		}
		return &Validator{reloadable: reloadable, opts: o}, nil
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	eng, err := engine.BuildFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Validator{engine: eng, opts: o}, nil
}

// Validate checks the password against all configured rules.
// The context can be used for cancellation in long-running operations.
// Returns a slice of validation errors, or an empty slice if the password is valid.
func (v *Validator) Validate(ctx context.Context, password string) []ValidationError {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return []ValidationError{{
			Code:    "CONTEXT_CANCELLED",
			Message: "validation cancelled",
		}}
	default:
	}

	if v.reloadable != nil {
		return v.reloadable.Validate(ctx, password, v.opts.failFast)
	}
	return v.engine.Validate(ctx, password, v.opts.failFast)
}

// Analyze performs a comprehensive password analysis and returns detailed results.
// This includes a strength score, entropy calculation, and improvement suggestions.
func (v *Validator) Analyze(ctx context.Context, password string) Result {
	errs := v.Validate(ctx, password)

	entropy := calculateEntropy(password)
	score := calculateScore(entropy, len(errs))
	strength := getStrengthLabel(score)
	suggestions := generateSuggestions(errs)

	return Result{
		Valid:       len(errs) == 0,
		Score:       score,
		Strength:    strength,
		Entropy:     entropy,
		Errors:      errs,
		Suggestions: suggestions,
	}
}

// Close releases any resources held by the validator.
// This should be called when using WithAutoReload to stop the file watcher.
func (v *Validator) Close() error {
	if v.reloadable != nil {
		return v.reloadable.Close()
	}
	return nil
}

// Metrics returns reload metrics when using WithAutoReload.
// Returns zero metrics if auto-reload is not enabled.
func (v *Validator) Metrics() engine.Metrics {
	if v.reloadable != nil {
		return v.reloadable.Metrics()
	}
	return engine.Metrics{}
}

// Helper functions for Analyze

func calculateEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	charsetSize := 0
	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasDigit {
		charsetSize += 10
	}
	if hasSpecial {
		charsetSize += 32
	}

	if charsetSize == 0 {
		return 0
	}

	// Entropy = log2(charset^length) = length * log2(charset)
	import_math := float64(charsetSize)
	entropy := float64(len(password)) * (logBase2(import_math))
	return entropy
}

func logBase2(x float64) float64 {
	// log2(x) = ln(x) / ln(2)
	// Using approximation for simplicity
	if x <= 0 {
		return 0
	}
	result := 0.0
	for x >= 2 {
		x /= 2
		result++
	}
	// Linear interpolation for fractional part
	result += (x - 1)
	return result
}

func calculateScore(entropy float64, errorCount int) int {
	// Base score from entropy (0-100)
	score := int(entropy * 1.2)
	if score > 100 {
		score = 100
	}

	// Penalty for each error
	score -= errorCount * 15
	if score < 0 {
		score = 0
	}

	return score
}

func getStrengthLabel(score int) string {
	switch {
	case score < 20:
		return "Very Weak"
	case score < 40:
		return "Weak"
	case score < 60:
		return "Fair"
	case score < 80:
		return "Strong"
	default:
		return "Very Strong"
	}
}

func generateSuggestions(errs []ValidationError) []string {
	suggestions := make([]string, 0)

	for _, e := range errs {
		switch e.Code {
		case "LENGTH_TOO_SHORT":
			suggestions = append(suggestions, "Add more characters to increase length")
		case "LOW_ENTROPY":
			suggestions = append(suggestions, "Use a mix of uppercase, lowercase, numbers, and symbols")
		case "SEQUENCE_TOO_LONG":
			suggestions = append(suggestions, "Avoid predictable sequences like 'abc' or '123'")
		case "CATEGORY_MIN_NOT_MET":
			suggestions = append(suggestions, "Include characters from different categories")
		}
	}

	if len(suggestions) == 0 && len(errs) > 0 {
		suggestions = append(suggestions, "Review the specific error messages for guidance")
	}

	return suggestions
}
