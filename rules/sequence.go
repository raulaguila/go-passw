package rules

import (
	"strings"

	"github.com/raulaguila/passvalidator/errors"
)

type SequenceRule struct {
	Max int
}

func NewSequenceRule(max int) *SequenceRule {
	return &SequenceRule{Max: max}
}

func (r *SequenceRule) Validate(p string) *errors.ValidationError {
	if r.Max <= 1 {
		return nil
	}

	runes := []rune(strings.ToLower(p))
	count := 1

	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1]+1 {
			count++
			if count > r.Max {
				return errors.New("SEQUENCE_TOO_LONG", "predictable sequence detected")
			}
		} else {
			count = 1
		}
	}

	return nil
}
