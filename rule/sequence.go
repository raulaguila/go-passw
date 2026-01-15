package rule

import (
	"strings"

	"github.com/raulaguila/passguard/errors"
)

// Keyboard layout rows for pattern detection
var keyboardRows = []string{
	"qwertyuiop",
	"asdfghjkl",
	"zxcvbnm",
	"1234567890",
	// Reversed rows (right-to-left patterns)
	"poiuytrewq",
	"lkjhgfdsa",
	"mnbvcxz",
	"0987654321",
}

// Common keyboard patterns (diagonal, etc.)
var keyboardPatterns = []string{
	"qazwsx",
	"wsxedc",
	"edcrfv",
	"rfvtgb",
	"tgbyhn",
	"yhnujm",
	"1qaz",
	"2wsx",
	"3edc",
	"4rfv",
	"5tgb",
	"6yhn",
	"7ujm",
	"1q2w3e",
	"q1w2e3",
	"zaq1",
	"xsw2",
	"cde3",
}

// SequenceRule validates that passwords don't contain predictable sequences.
type SequenceRule struct {
	max             int
	includeKeyboard bool
}

// NewSequenceRule creates a new sequence validation rule.
// max is the maximum allowed consecutive sequence length (e.g., "abc" = 3).
func NewSequenceRule(max int) *SequenceRule {
	return &SequenceRule{max: max, includeKeyboard: true}
}

// NewSequenceRuleWithKeyboard creates a sequence rule with configurable keyboard detection.
func NewSequenceRuleWithKeyboard(max int, includeKeyboard bool) *SequenceRule {
	return &SequenceRule{max: max, includeKeyboard: includeKeyboard}
}

// Name returns the rule identifier.
func (r *SequenceRule) Name() string {
	return "sequence"
}

// Validate checks if the password contains predictable sequences.
func (r *SequenceRule) Validate(password string) *errors.ValidationError {
	if r.max <= 1 {
		return nil
	}

	lower := strings.ToLower(password)

	// Check keyboard patterns first (if enabled)
	if r.includeKeyboard {
		if err := r.checkKeyboardPatterns(lower); err != nil {
			return err
		}
	}

	// Check consecutive sequences (abc, 123, etc.)
	return r.checkConsecutiveSequences(lower)
}

// checkKeyboardPatterns looks for keyboard row patterns and common patterns.
func (r *SequenceRule) checkKeyboardPatterns(password string) *errors.ValidationError {
	// Check for patterns in keyboard rows
	for _, row := range keyboardRows {
		if pattern := r.findPatternInRow(password, row); pattern != "" {
			return errors.New(
				"KEYBOARD_PATTERN",
				"Keyboard pattern detected.",
			).WithDetails(map[string]any{
				"pattern":     pattern,
				"type":        "keyboard_row",
				"max_allowed": r.max,
				"found":       len(pattern),
			})
		}
	}

	// Check for known keyboard patterns
	for _, pattern := range keyboardPatterns {
		if len(pattern) > r.max && strings.Contains(password, pattern) {
			return errors.New(
				"KEYBOARD_PATTERN",
				"Keyboard pattern detected.",
			).WithDetails(map[string]any{
				"pattern":     pattern,
				"type":        "common_pattern",
				"max_allowed": r.max,
				"found":       len(pattern),
			})
		}
	}

	return nil
}

// findPatternInRow finds sequential patterns from a keyboard row in the password.
func (r *SequenceRule) findPatternInRow(password, row string) string {
	for i := 0; i <= len(row)-r.max-1; i++ {
		pattern := row[i : i+r.max+1]
		if strings.Contains(password, pattern) {
			return pattern
		}
	}
	return ""
}

// checkConsecutiveSequences looks for ascending/descending character sequences.
func (r *SequenceRule) checkConsecutiveSequences(password string) *errors.ValidationError {
	runes := []rune(password)

	// Check ascending sequences (abc, 123)
	if err := r.checkDirectionalSequence(runes, 1, "ascending"); err != nil {
		return err
	}

	// Check descending sequences (cba, 321)
	if err := r.checkDirectionalSequence(runes, -1, "descending"); err != nil {
		return err
	}

	return nil
}

// checkDirectionalSequence checks for sequences in a specific direction.
func (r *SequenceRule) checkDirectionalSequence(runes []rune, direction int, seqType string) *errors.ValidationError {
	count := 1
	sequence := ""

	for i := 1; i < len(runes); i++ {
		diff := int(runes[i]) - int(runes[i-1])

		if diff == direction {
			if count == 1 {
				sequence = string(runes[i-1])
			}
			sequence += string(runes[i])
			count++

			if count > r.max {
				return errors.New(
					"SEQUENCE_TOO_LONG",
					"Predictable sequence detected.",
				).WithDetails(map[string]any{
					"sequence":    sequence,
					"type":        seqType,
					"max_allowed": r.max,
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
