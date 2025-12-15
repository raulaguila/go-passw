package rules

import "github.com/raulaguila/passvalidator/errors"

type Rule interface {
	Validate(password string) *errors.ValidationError
}
