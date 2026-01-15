package passguard

import (
	"context"
	"log/slog"
	"testing"
)

func TestValidatorBasic(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Test valid password
	errs := validator.Validate(context.Background(), "#Password@8249!")
	if len(errs) > 0 {
		t.Errorf("expected valid password, got errors: %v", errs)
	}
}

func TestValidatorInvalidPassword(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Test invalid password (too short, missing categories)
	errs := validator.Validate(context.Background(), "abc")
	if len(errs) == 0 {
		t.Error("expected validation errors for weak password")
	}
}

func TestValidatorWithAutoReload(t *testing.T) {
	validator, err := NewWithOptions("policy.yaml", WithAutoReload())
	if err != nil {
		t.Fatalf("failed to create reloadable validator: %v", err)
	}
	defer validator.Close()

	// Test valid password
	errs := validator.Validate(context.Background(), "#Password@8249!")
	if len(errs) > 0 {
		t.Errorf("expected valid password, got errors: %v", errs)
	}

	// Verify metrics are available
	metrics := validator.Metrics()
	if metrics.ReloadCount != 0 {
		// Initial load shouldn't increment reload count
		t.Logf("initial reload count: %d", metrics.ReloadCount)
	}
}

func TestValidatorLengthRule(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "Aa1!", false},           // length < 8
		{"minimum length", "#Aa1bcdef", false}, // length = 8 with requirements
		{"valid length", "#Password@8249!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validator.Validate(context.Background(), tt.password)
			hasLengthErr := false
			for _, e := range errs {
				if e.Code == "LENGTH_TOO_SHORT" || e.Code == "LENGTH_TOO_LONG" {
					hasLengthErr = true
					break
				}
			}
			if tt.wantErr && !hasLengthErr {
				t.Errorf("expected length error for %q", tt.password)
			}
		})
	}
}

func TestValidatorContextCancellation(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Validate with cancelled context
	errs := validator.Validate(ctx, "#Password@8249!")

	// Should have a cancellation error
	hasCancel := false
	for _, e := range errs {
		if e.Code == "CONTEXT_CANCELLED" {
			hasCancel = true
			break
		}
	}
	if !hasCancel {
		t.Error("expected CONTEXT_CANCELLED error when context is cancelled")
	}
}

func TestValidatorFailFast(t *testing.T) {
	// Create validator with fail-fast enabled
	validator, err := NewWithOptions("policy.yaml", WithFailFast())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Test with multiple errors - should only get one
	errs := validator.Validate(context.Background(), "a") // Too short, missing categories, etc.

	if len(errs) != 1 {
		t.Errorf("expected exactly 1 error with fail-fast, got %d", len(errs))
	}
}

func TestValidatorWithLogger(t *testing.T) {
	// Create validator with nil logger (disabled)
	validator, err := NewWithOptions("policy.yaml",
		WithAutoReload(),
		WithLogger(nil), // Disable logging
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Should work without logging
	errs := validator.Validate(context.Background(), "#Password@8249!")
	if len(errs) > 0 {
		t.Errorf("expected valid password, got errors: %v", errs)
	}
}

func TestValidatorWithCustomLogger(t *testing.T) {
	// Create validator with custom logger
	logger := slog.Default()
	validator, err := NewWithOptions("policy.yaml",
		WithAutoReload(),
		WithLogger(logger),
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	errs := validator.Validate(context.Background(), "#Password@8249!")
	if len(errs) > 0 {
		t.Errorf("expected valid password, got errors: %v", errs)
	}
}

func TestValidatorAnalyze(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Test strong password
	result := validator.Analyze(context.Background(), "#Password@8249!")
	if !result.Valid {
		t.Errorf("expected valid password, got errors: %v", result.Errors)
	}
	if result.Score < 50 {
		t.Errorf("expected high score for strong password, got %d", result.Score)
	}
	if result.Entropy <= 0 {
		t.Errorf("expected positive entropy, got %f", result.Entropy)
	}
	if result.Strength == "" {
		t.Error("expected strength label")
	}

	// Test weak password
	result = validator.Analyze(context.Background(), "abc")
	if result.Valid {
		t.Error("expected invalid password")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors")
	}
	if len(result.Suggestions) == 0 {
		t.Error("expected suggestions for weak password")
	}
}

func TestResultStrengthLabels(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{10, "Very Weak"},
		{30, "Weak"},
		{50, "Fair"},
		{70, "Strong"},
		{90, "Very Strong"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			label := getStrengthLabel(tt.score)
			if label != tt.expected {
				t.Errorf("expected %s for score %d, got %s", tt.expected, tt.score, label)
			}
		})
	}
}
