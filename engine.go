package passvalidator

import (
	"github.com/raulaguila/passvalidator/errors"
	"github.com/raulaguila/passvalidator/rules"
)

type PolicyEngine struct {
	rules []rules.Rule
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{}
}

func (e *PolicyEngine) AddRule(r rules.Rule) {
	e.rules = append(e.rules, r)
}

func (e *PolicyEngine) Validate(p string) []errors.ValidationError {
	var errs []errors.ValidationError

	for _, r := range e.rules {
		if err := r.Validate(p); err != nil {
			errs = append(errs, *err)
		}
	}

	return errs
}
