package passguard

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode"
)

func TestValidatorGenerate(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	ctx := context.Background()

	// Generate password
	password, err := validator.Generate(ctx)
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}

	// Check length (default 16)
	if len(password) < 16 {
		t.Errorf("expected password length >= 16, got %d", len(password))
	}

	// Validate the generated password
	errs := validator.Validate(ctx, password)
	if len(errs) > 0 {
		t.Errorf("generated password failed validation: %v", errs)
	}

	t.Logf("Generated password: %s", password)
}

func TestValidatorGenerateWithLength(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	ctx := context.Background()

	// Generate with custom length
	password, err := validator.Generate(ctx, WithLength(24))
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}

	if len(password) < 24 {
		t.Errorf("expected password length >= 24, got %d", len(password))
	}

	t.Logf("Generated password (24): %s", password)
}

func TestValidatorGenerateExcludeAmbiguous(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	ctx := context.Background()

	// Generate without ambiguous characters
	password, err := validator.Generate(ctx, WithExcludeAmbiguous())
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}

	// Check for ambiguous characters
	ambiguous := "0O1lI"
	for _, ch := range password {
		if strings.ContainsRune(ambiguous, ch) {
			t.Errorf("password contains ambiguous character: %c", ch)
		}
	}

	t.Logf("Generated password (no ambiguous): %s", password)
}

func TestValidatorGenerateCategories(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	ctx := context.Background()

	// Generate multiple passwords and check categories
	for i := 0; i < 10; i++ {
		password, err := validator.Generate(ctx)
		if err != nil {
			t.Fatalf("failed to generate password: %v", err)
		}

		hasLower := false
		hasUpper := false
		hasDigit := false
		hasSpecial := false

		for _, ch := range password {
			switch {
			case unicode.IsLower(ch):
				hasLower = true
			case unicode.IsUpper(ch):
				hasUpper = true
			case unicode.IsDigit(ch):
				hasDigit = true
			case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
				hasSpecial = true
			}
		}

		if !hasLower {
			t.Errorf("password missing lowercase: %s", password)
		}
		if !hasUpper {
			t.Errorf("password missing uppercase: %s", password)
		}
		if !hasDigit {
			t.Errorf("password missing digit: %s", password)
		}
		if !hasSpecial {
			t.Errorf("password missing special: %s", password)
		}
	}
}

func TestValidatorGenerateContextCancellation(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = validator.Generate(ctx)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestValidatorGenerateMinLength(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	ctx := context.Background()

	// Try to generate with too short length
	_, err = validator.Generate(ctx, WithLength(2))
	if err == nil {
		t.Error("expected error for too short length")
	}
}

func TestValidatorGenerateUniqueness(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	ctx := context.Background()

	// Generate multiple passwords and check they're unique
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		password, err := validator.Generate(ctx)
		if err != nil {
			t.Fatalf("failed to generate password: %v", err)
		}
		if passwords[password] {
			t.Errorf("generated duplicate password: %s", password)
		}
		passwords[password] = true
	}
}

func TestValidatorGeneratePerformance(t *testing.T) {
	validator, err := New("policy.yaml")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	defer validator.Close()

	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 1000; i++ {
		_, err := validator.Generate(ctx)
		if err != nil {
			t.Fatalf("failed to generate password: %v", err)
		}
	}
	elapsed := time.Since(start)

	t.Logf("Generated 1000 passwords in %v (%.2f per second)", elapsed, 1000/elapsed.Seconds())

	// Should be able to generate at least 100 passwords per second
	if elapsed.Seconds() > 10 {
		t.Errorf("password generation too slow: %v for 1000 passwords", elapsed)
	}
}
