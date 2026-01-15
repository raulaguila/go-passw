// Package rule defines the Rule interface and validation rule implementations.
package rule

import "github.com/raulaguila/passguard/errors"

// Rule defines the interface for password validation rules.
// Implementations should be stateless and safe for concurrent use.
type Rule interface {
	// Name returns the unique identifier for this rule.
	// Used for logging and metrics purposes.
	Name() string

	// Validate checks if the password meets the rule requirements.
	// Returns nil if the password is valid, or a ValidationError otherwise.
	Validate(password string) *errors.ValidationError
}
