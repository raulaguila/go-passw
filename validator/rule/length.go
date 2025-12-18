package rule

import (
	"fmt"

	errPassw "github.com/raulaguila/go-passw/validator/errors"
)

type LengthRule struct {
	Min int
	Max int
}

func NewLengthRule(min, max int) *LengthRule {
	return &LengthRule{Min: min, Max: max}
}

func (r *LengthRule) Validate(password string) *errPassw.ValidationError {
	l := len([]rune(password))
	if l < r.Min {
		return errPassw.New("LENGTH_TOO_SHORT", fmt.Sprintf("Password must have at least %d characters.", r.Min)).WithDetails(map[string]any{
			"required": r.Min,
			"found":    l,
		})
	}

	if r.Max > 0 && l > r.Max {
		return errPassw.New("LENGTH_TOO_LONG", fmt.Sprintf("Password must have a maximum of %d characters.", r.Max)).WithDetails(map[string]any{
			"required": r.Max,
			"found":    l,
		})
	}

	return nil
}
