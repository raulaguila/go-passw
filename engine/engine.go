// Package engine provides the password validation engine.
package engine

import (
	"context"

	"github.com/raulaguila/passguard/errors"
	"github.com/raulaguila/passguard/rule"
)

// Engine validates passwords against a set of rules.
type Engine struct {
	rules []rule.Rule
}

// New creates a new validation engine.
func New() *Engine {
	return &Engine{
		rules: make([]rule.Rule, 0),
	}
}

// AddRule adds a validation rule to the engine.
func (e *Engine) AddRule(r rule.Rule) {
	e.rules = append(e.rules, r)
}

// Rules returns the current list of rules.
func (e *Engine) Rules() []rule.Rule {
	return e.rules
}

// Validate checks the password against all rules and returns all errors.
// The context can be used for cancellation between rule validations.
// If failFast is true, validation stops at the first error.
func (e *Engine) Validate(ctx context.Context, password string, failFast bool) []errors.ValidationError {
	var errs []errors.ValidationError

	for _, r := range e.rules {
		// Check for context cancellation between rules
		select {
		case <-ctx.Done():
			errs = append(errs, errors.ValidationError{
				Code:    "CONTEXT_CANCELLED",
				Message: "validation cancelled",
			})
			return errs
		default:
		}

		if err := r.Validate(password); err != nil {
			errs = append(errs, *err)
			if failFast {
				return errs
			}
		}
	}

	return errs
}
