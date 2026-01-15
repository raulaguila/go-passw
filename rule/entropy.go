package rule

import (
	"math"
	"strings"
	"unicode"

	"github.com/raulaguila/passguard/errors"
)

// EntropyRule validates password entropy (randomness/strength).
type EntropyRule struct {
	minEntropy     float64
	blacklist      []string
	blacklistBoost float64
}

// NewEntropyRule creates a new entropy validation rule.
//
// Parameters:
//   - minEntropy: minimum required entropy bits (e.g., 60 for strong passwords)
//   - blacklist: list of common words/patterns that reduce entropy
//   - blacklistBoost: penalty applied for each blacklisted word found
func NewEntropyRule(minEntropy float64, blacklist []string, blacklistBoost float64) *EntropyRule {
	return &EntropyRule{
		minEntropy:     minEntropy,
		blacklist:      blacklist,
		blacklistBoost: blacklistBoost,
	}
}

// Name returns the rule identifier.
func (r *EntropyRule) Name() string {
	return "entropy"
}

// Validate checks if the password has sufficient entropy.
func (r *EntropyRule) Validate(password string) *errors.ValidationError {
	entropy := r.calculateEntropy(password)
	penalty := r.calculatePenalty(password)
	finalEntropy := entropy - penalty

	if finalEntropy < r.minEntropy {
		return errors.New(
			"LOW_ENTROPY",
			"Weak password: insufficient entropy",
		).WithDetails(map[string]any{
			"strength":          r.getPasswordStrength(finalEntropy),
			"entropy":           entropy,
			"penalty":           penalty,
			"final_entropy":     finalEntropy,
			"required_entropy":  r.minEntropy,
			"required_strength": r.getPasswordStrength(r.minEntropy),
		})
	}

	return nil
}

// calculateEntropy computes the theoretical entropy of the password.
func (r *EntropyRule) calculateEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	charsetSize := r.calculateCharsetSize(password)
	return math.Log2(math.Pow(float64(charsetSize), float64(len(password))))
}

// calculateCharsetSize determines the character set size based on character types used.
func (r *EntropyRule) calculateCharsetSize(password string) int {
	var hasLower, hasUpper, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}

		// Early exit if all character types detected
		if hasLower && hasUpper && hasDigit && hasSpecial {
			break
		}
	}

	charsetSize := 0
	if hasLower {
		charsetSize += 26 // a-z
	}
	if hasUpper {
		charsetSize += 26 // A-Z
	}
	if hasDigit {
		charsetSize += 10 // 0-9
	}
	if hasSpecial {
		charsetSize += 32 // Common special characters
	}

	return charsetSize
}

// calculatePenalty computes entropy penalty for blacklisted words.
func (r *EntropyRule) calculatePenalty(password string) float64 {
	penalty := 0.0
	lowerPassword := strings.ToLower(password)

	for _, blacklisted := range r.blacklist {
		if strings.Contains(lowerPassword, strings.ToLower(blacklisted)) {
			penalty += r.blacklistBoost
		}
	}

	return penalty
}

// getPasswordStrength returns a human-readable strength label.
func (r *EntropyRule) getPasswordStrength(entropy float64) string {
	switch {
	case entropy < 30:
		return "Very Weak"
	case entropy < 40:
		return "Weak"
	case entropy < 50:
		return "Medium"
	case entropy < 60:
		return "Strong"
	case entropy < 80:
		return "Very Strong"
	default:
		return "Extremely Strong"
	}
}
