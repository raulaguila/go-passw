package rules

import (
	"fmt"

	"github.com/raulaguila/passvalidator/errors"
)

type LengthRule struct {
	Min int
	Max int
}

func NewLengthRule(min, max int) *LengthRule {
	return &LengthRule{Min: min, Max: max}
}

func (r *LengthRule) Validate(password string) *errors.ValidationError {
	l := len([]rune(password))
	if l < r.Min {
		return errors.New("LENGTH_TOO_SHORT", fmt.Sprintf("The password must have at least %d characters.", r.Min)).WithDetails(map[string]any{
			"required": r.Min,
			"found":    l,
		})
	}

	if r.Max > 0 && l > r.Max {
		return errors.New("LENGTH_TOO_LONG", fmt.Sprintf("The password must have a maximum of %d characters.", r.Max)).WithDetails(map[string]any{
			"required": r.Min,
			"found":    l,
		})
	}

	return nil
}
