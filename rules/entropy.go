package rules

import (
	"math"
	"strings"

	"github.com/raulaguila/passvalidator/errors"
)

type EntropyRule struct {
	MinEntropy     float64
	Blacklist      []string
	BlacklistBoost float64
}

func NewEntropyRule(minEntropy float64, blacklist []string, blacklistBoost float64) *EntropyRule {
	return &EntropyRule{
		MinEntropy:     minEntropy,
		Blacklist:      blacklist,
		BlacklistBoost: blacklistBoost,
	}
}

func (e EntropyRule) Validate(password string) *errors.ValidationError {
	entropy := calculateEntropy(password)

	penalty := 0.0
	lower := strings.ToLower(password)
	for _, word := range e.Blacklist {
		if strings.Contains(lower, strings.ToLower(word)) {
			penalty += e.BlacklistBoost
		}
	}

	finalEntropy := entropy - penalty

	if finalEntropy < e.MinEntropy {
		return errors.New("LOW_ENTROPY", "Weak password: insufficient entropy").WithDetails(map[string]any{
			"entropy":       entropy,
			"penalty":       penalty,
			"final_entropy": finalEntropy,
			"required":      e.MinEntropy,
		})
	}

	return nil
}

func calculateEntropy(password string) float64 {
	runes := []rune(password)
	length := float64(len(runes))
	if length == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range runes {
		freq[r]++
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy * length
}
