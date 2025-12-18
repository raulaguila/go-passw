package rule

import errPassw "github.com/raulaguila/go-passw/validator/errors"

type Rule interface {
	Validate(password string) *errPassw.ValidationError
}
