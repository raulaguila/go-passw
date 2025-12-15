package passvalidator

import (
	"fmt"

	"errors"
)

func Example(pwd string) error {
	engine, err := NewPolicyEngineReloadable("policy.yaml")
	if err != nil {
		return err
	}

	if errs := engine.Validate(pwd); len(errs) > 0 {
		fmt.Println("invalid password")
		for _, e := range errs {
			fmt.Printf("- %+v\n", e)
		}
		return errors.New("error to validate")
	}

	return nil
}
