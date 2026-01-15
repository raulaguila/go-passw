package rule

import (
	"fmt"

	"github.com/raulaguila/passguard/errors"
)

// LengthRule validates password length requirements.
type LengthRule struct {
	min int
	max int
}

// NewLengthRule creates a new length validation rule.
// If max is 0 or negative, no maximum length is enforced.
func NewLengthRule(min, max int) *LengthRule {
	return &LengthRule{min: min, max: max}
}

// Name returns the rule identifier.
func (r *LengthRule) Name() string {
	return "length"
}

// Validate checks if the password length is within bounds.
func (r *LengthRule) Validate(password string) *errors.ValidationError {
	length := len([]rune(password))

	if length < r.min {
		return errors.New(
			"LENGTH_TOO_SHORT",
			fmt.Sprintf("Password must have at least %d characters.", r.min),
		).WithDetails(map[string]any{
			"required": r.min,
			"found":    length,
		})
	}

	if r.max > 0 && length > r.max {
		return errors.New(
			"LENGTH_TOO_LONG",
			fmt.Sprintf("Password must have a maximum of %d characters.", r.max),
		).WithDetails(map[string]any{
			"required": r.max,
			"found":    length,
		})
	}

	return nil
}
