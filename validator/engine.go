package validator

import (
	errPassw "github.com/raulaguila/go-passw/validator/errors"
	"github.com/raulaguila/go-passw/validator/rule"
)

type PolicyEngine struct {
	rules []rule.Rule
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{}
}

func (e *PolicyEngine) AddRule(r rule.Rule) {
	e.rules = append(e.rules, r)
}

func (e *PolicyEngine) Validate(p string) []errPassw.ValidationError {
	var errs []errPassw.ValidationError

	for _, r := range e.rules {
		if err := r.Validate(p); err != nil {
			errs = append(errs, *err)
		}
	}

	return errs
}
