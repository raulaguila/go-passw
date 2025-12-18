package rule

import (
	"strings"

	errPassw "github.com/raulaguila/go-passw/validator/errors"
)

type SequenceRule struct {
	Max int
}

func NewSequenceRule(max int) *SequenceRule {
	return &SequenceRule{Max: max}
}

func (r *SequenceRule) Validate(p string) *errPassw.ValidationError {
	if r.Max <= 1 {
		return nil
	}

	runes := []rune(strings.ToLower(p))
	count := 1
	sequence := ""

	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1]+1 {
			sequence += string(runes[i-1])
			count++
			if count > r.Max {
				sequence += string(runes[i])
				return errPassw.New("SEQUENCE_TOO_LONG", "Predictable sequence detected.").WithDetails(map[string]any{
					"sequence":    sequence,
					"max_allowed": r.Max,
					"found":       count,
				})
			}
		} else {
			count = 1
			sequence = ""
		}
	}

	return nil
}
