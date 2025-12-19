package rule

import (
	"math"
	"strings"
	"unicode"

	errPassw "github.com/raulaguila/go-passw/validator/errors"
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

func (e EntropyRule) Validate(password string) *errPassw.ValidationError {
	entropy := e.calculateEntropy(password)
	penalty := e.calculatePenalty(password)

	finalEntropy := entropy - penalty

	if finalEntropy < e.MinEntropy {
		return errPassw.New("LOW_ENTROPY", "Weak password: insufficient entropy").WithDetails(map[string]any{
			"strength":          e.getPasswordStrength(finalEntropy),
			"entropy":           entropy,
			"penalty":           penalty,
			"final_entropy":     finalEntropy,
			"required_entropy":  e.MinEntropy,
			"required_strength": e.getPasswordStrength(e.MinEntropy),
		})
	}

	return nil
}

func (e EntropyRule) calculateEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	charsetSize := e.calculateCharsetSize(password)
	entropy := math.Log2(math.Pow(float64(charsetSize), float64(len(password))))

	return entropy
}

func (e EntropyRule) calculateCharsetSize(password string) int {
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false

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
		charsetSize += 32 // Common special characters (!@#$%^&*()_+-=[]{}|;:',.<>?/\`)
	}

	return charsetSize
}

func (e EntropyRule) calculatePenalty(password string) float64 {
	penalty := 0.0
	lowerPassword := strings.ToLower(password)

	for _, blacklisted := range e.Blacklist {
		if strings.Contains(lowerPassword, strings.ToLower(blacklisted)) {
			penalty += e.BlacklistBoost
		}
	}

	return penalty
}

func (e EntropyRule) getPasswordStrength(entropy float64) string {
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
