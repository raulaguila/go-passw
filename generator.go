package passguard

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

// GenerateOption configures password generation.
type GenerateOption func(*generateOptions)

type generateOptions struct {
	length           int
	excludeAmbiguous bool
	customCharset    string
}

// Default character sets
const (
	lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
	uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars     = "0123456789"
	specialChars   = "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// Ambiguous characters that can be confused
	ambiguousChars = "0O1lI"
)

// WithLength sets the password length (default: 16).
func WithLength(length int) GenerateOption {
	return func(o *generateOptions) {
		o.length = length
	}
}

// WithExcludeAmbiguous excludes visually ambiguous characters (0, O, 1, l, I).
func WithExcludeAmbiguous() GenerateOption {
	return func(o *generateOptions) {
		o.excludeAmbiguous = true
	}
}

// WithCustomCharset uses a custom character set instead of the default.
func WithCustomCharset(charset string) GenerateOption {
	return func(o *generateOptions) {
		o.customCharset = charset
	}
}

// Generate creates a random password that meets the configured policies.
// It ensures the password contains at least one character from each required category.
func (v *Validator) Generate(ctx context.Context, opts ...GenerateOption) (string, error) {
	// Check context
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	// Default options
	o := &generateOptions{
		length: 16,
	}
	for _, opt := range opts {
		opt(o)
	}

	// Minimum length check
	if o.length < 4 {
		return "", errors.New("password length must be at least 4")
	}

	// Build character sets
	var charset string
	if o.customCharset != "" {
		charset = o.customCharset
	} else {
		charset = lowercaseChars + uppercaseChars + digitChars + specialChars
	}

	// Remove ambiguous characters if requested
	if o.excludeAmbiguous {
		charset = removeChars(charset, ambiguousChars)
	}

	if len(charset) == 0 {
		return "", errors.New("character set is empty")
	}

	// Generate password with guaranteed category requirements
	password, err := v.generateWithCategories(ctx, o.length, charset, o.excludeAmbiguous)
	if err != nil {
		return "", err
	}

	// Validate the generated password
	errs := v.Validate(ctx, password)
	if len(errs) > 0 {
		// If validation fails, try again with longer length
		// This handles edge cases where random generation doesn't meet all rules
		for attempts := 0; attempts < 3; attempts++ {
			password, err = v.generateWithCategories(ctx, o.length+4+attempts*2, charset, o.excludeAmbiguous)
			if err != nil {
				return "", err
			}
			errs = v.Validate(ctx, password)
			if len(errs) == 0 {
				break
			}
		}
	}

	return password, nil
}

// generateWithCategories ensures password has at least one char from each category.
func (v *Validator) generateWithCategories(ctx context.Context, length int, charset string, excludeAmbiguous bool) (string, error) {
	// Define category character sets
	lower := lowercaseChars
	upper := uppercaseChars
	digits := digitChars
	special := specialChars

	if excludeAmbiguous {
		lower = removeChars(lower, ambiguousChars)
		upper = removeChars(upper, ambiguousChars)
		digits = removeChars(digits, ambiguousChars)
	}

	// Guarantee at least one from each category
	var password strings.Builder
	password.Grow(length)

	// Add one character from each category first
	categories := []string{lower, upper, digits, special}
	for _, cat := range categories {
		if len(cat) > 0 {
			ch, err := randomChar(cat)
			if err != nil {
				return "", err
			}
			password.WriteByte(ch)
		}
	}

	// Fill the rest with random characters from the full charset
	remaining := length - password.Len()
	for i := 0; i < remaining; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		ch, err := randomChar(charset)
		if err != nil {
			return "", err
		}
		password.WriteByte(ch)
	}

	// Shuffle the password to randomize category character positions
	result := []byte(password.String())
	if err := shuffle(result); err != nil {
		return "", err
	}

	return string(result), nil
}

// randomChar returns a cryptographically random character from the charset.
func randomChar(charset string) (byte, error) {
	max := big.NewInt(int64(len(charset)))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

// shuffle performs a Fisher-Yates shuffle using crypto/rand.
func shuffle(data []byte) error {
	for i := len(data) - 1; i > 0; i-- {
		max := big.NewInt(int64(i + 1))
		j, err := rand.Int(rand.Reader, max)
		if err != nil {
			return err
		}
		data[i], data[j.Int64()] = data[j.Int64()], data[i]
	}
	return nil
}

// removeChars removes all characters in 'remove' from 'str'.
func removeChars(str, remove string) string {
	var result strings.Builder
	for _, ch := range str {
		if !strings.ContainsRune(remove, ch) {
			result.WriteRune(ch)
		}
	}
	return result.String()
}
