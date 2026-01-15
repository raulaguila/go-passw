package rule

import (
	"testing"
)

func TestLengthRule(t *testing.T) {
	tests := []struct {
		name     string
		min      int
		max      int
		password string
		wantCode string
	}{
		{"too short", 8, 128, "short", "LENGTH_TOO_SHORT"},
		{"too long", 8, 10, "thispasswordistoolong", "LENGTH_TOO_LONG"},
		{"min boundary pass", 8, 128, "12345678", ""},
		{"max boundary pass", 8, 10, "1234567890", ""},
		{"no max limit", 8, 0, "12345678901234567890", ""},
		{"unicode chars", 4, 10, "日本語テスト", ""},
		{"unicode too short", 4, 10, "日本", "LENGTH_TOO_SHORT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewLengthRule(tt.min, tt.max)

			if rule.Name() != "length" {
				t.Errorf("expected name 'length', got %s", rule.Name())
			}

			err := rule.Validate(tt.password)

			if tt.wantCode == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error with code %s, got nil", tt.wantCode)
				} else if err.Code != tt.wantCode {
					t.Errorf("expected code %s, got %s", tt.wantCode, err.Code)
				}
			}
		})
	}
}

func TestEntropyRule(t *testing.T) {
	rule := NewEntropyRule(60, []string{"password", "123"}, 8)

	if rule.Name() != "entropy" {
		t.Errorf("expected name 'entropy', got %s", rule.Name())
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"strong password", "#Password@8249!xyz", false},
		{"weak - short", "abc", true},
		{"weak - blacklisted", "mypassword123", true},
		{"mixed chars", "aA1!aA1!aA1!aA1!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rule.Validate(tt.password)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestSequenceRule(t *testing.T) {
	tests := []struct {
		name      string
		max       int
		password  string
		wantCode  string
		acceptAny []string // Accept any of these codes (for overlapping patterns)
	}{
		{"no sequence", 3, "azbycx", "", nil},
		{"sequence at limit", 3, "abc123", "", nil},
		{"sequence too long", 3, "abcdxyz", "SEQUENCE_TOO_LONG", nil},
		{"numbers sequence or keyboard", 3, "pass1234", "", []string{"SEQUENCE_TOO_LONG", "KEYBOARD_PATTERN"}},
		{"disabled when max <= 1", 1, "abcdefgh", "", nil},
		// Descending sequences
		{"descending letters", 3, "passdcba", "SEQUENCE_TOO_LONG", nil},
		{"descending numbers or keyboard", 3, "pass4321", "", []string{"SEQUENCE_TOO_LONG", "KEYBOARD_PATTERN"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSequenceRule(tt.max)

			if rule.Name() != "sequence" {
				t.Errorf("expected name 'sequence', got %s", rule.Name())
			}

			err := rule.Validate(tt.password)

			if tt.acceptAny != nil {
				// Accept any of the listed codes
				if err == nil {
					t.Errorf("expected error with one of %v, got nil", tt.acceptAny)
					return
				}
				found := false
				for _, code := range tt.acceptAny {
					if err.Code == code {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected one of %v, got %s", tt.acceptAny, err.Code)
				}
			} else if tt.wantCode == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error with code %s, got nil", tt.wantCode)
				} else if err.Code != tt.wantCode {
					t.Errorf("expected code %s, got %s", tt.wantCode, err.Code)
				}
			}
		})
	}
}

func TestSequenceRuleKeyboardPatterns(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantCode string
	}{
		// Keyboard row patterns
		{"qwerty pattern", "myqwertypass", "KEYBOARD_PATTERN"},
		{"asdfgh pattern", "asdfghtest", "KEYBOARD_PATTERN"},
		{"zxcvbn pattern", "testzxcvbn", "KEYBOARD_PATTERN"},
		// Reversed patterns
		{"poiuyt pattern", "testpoiuyt", "KEYBOARD_PATTERN"},
		// Diagonal patterns
		{"qazwsx pattern", "testqazwsx", "KEYBOARD_PATTERN"},
		{"1q2w3e pattern", "pass1q2w3e", "KEYBOARD_PATTERN"},
		// Clean passwords
		{"no keyboard pattern", "#Password@8249!", ""},
		{"random chars", "xKm9$pQr2!", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSequenceRuleWithKeyboard(3, true)
			err := rule.Validate(tt.password)

			if tt.wantCode == "" {
				if err != nil {
					t.Errorf("expected no error, got %v (code: %s)", err, err.Code)
				}
			} else {
				if err == nil {
					t.Errorf("expected error with code %s, got nil", tt.wantCode)
				} else if err.Code != tt.wantCode {
					t.Errorf("expected code %s, got %s", tt.wantCode, err.Code)
				}
			}
		})
	}
}

func TestSequenceRuleKeyboardDisabled(t *testing.T) {
	// With keyboard detection disabled, qwerty should pass
	rule := NewSequenceRuleWithKeyboard(3, false)
	err := rule.Validate("myqwertypass")

	// Should not detect keyboard pattern when disabled
	if err != nil && err.Code == "KEYBOARD_PATTERN" {
		t.Error("keyboard pattern should not be detected when disabled")
	}
}

func TestCategoryRule(t *testing.T) {
	categories := []Category{
		{Name: "uppercase", Min: 1, Predicate: GetPredicate("upper")},
		{Name: "lowercase", Min: 1, Predicate: GetPredicate("lower")},
		{Name: "number", Min: 1, Predicate: GetPredicate("number")},
		{Name: "special", Min: 1, Predicate: GetPredicate("special")},
	}
	rule := NewCategoryRule(categories)

	if rule.Name() != "category" {
		t.Errorf("expected name 'category', got %s", rule.Name())
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"all categories", "Aa1!", false},
		{"missing uppercase", "aa1!", true},
		{"missing lowercase", "AA1!", true},
		{"missing number", "AAa!", true},
		{"missing special", "AAa1", true},
		{"multiple of each", "AAaa11!!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rule.Validate(tt.password)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestPredicateRegistry(t *testing.T) {
	// Test built-in predicates
	predicates := ListPredicates()
	if len(predicates) < 4 {
		t.Errorf("expected at least 4 predicates, got %d", len(predicates))
	}

	// Test getting predicates
	upper := GetPredicate("upper")
	if upper == nil {
		t.Error("expected upper predicate, got nil")
	}
	if !upper('A') || upper('a') {
		t.Error("upper predicate not working correctly")
	}

	// Test custom predicate registration
	RegisterPredicate("vowel", func(r rune) bool {
		return r == 'a' || r == 'e' || r == 'i' || r == 'o' || r == 'u'
	})

	vowel := GetPredicate("vowel")
	if vowel == nil {
		t.Error("expected vowel predicate, got nil")
	}
	if !vowel('a') || vowel('b') {
		t.Error("vowel predicate not working correctly")
	}

	// Test unknown predicate
	unknown := GetPredicate("nonexistent")
	if unknown != nil {
		t.Error("expected nil for unknown predicate")
	}
}
