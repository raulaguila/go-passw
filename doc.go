// Package passguard provides a flexible, extensible password validation library.
//
// The library supports configurable validation policies loaded from YAML files,
// with optional hot-reload capabilities for dynamic policy updates without
// application restarts.
//
// # Basic Usage
//
//	validator, err := passguard.New("policy.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer validator.Close()
//
//	errs := validator.Validate(context.Background(), "mypassword123")
//	if len(errs) > 0 {
//	    for _, e := range errs {
//	        fmt.Printf("Validation error: %s\n", e.Message)
//	    }
//	}
//
// # With Auto-Reload
//
//	validator, err := passguard.NewWithOptions("policy.yaml",
//	    passguard.WithAutoReload(),
//	)
//
// # Available Rules
//
// The library includes the following validation rules:
//
//   - Length: Validates minimum and maximum password length
//   - Entropy: Calculates password entropy with blacklist penalties
//   - Sequence: Detects predictable character sequences
//   - Category: Requires specific character categories (uppercase, lowercase, digits, special)
//
// # Configuration
//
// Policies are defined in YAML format. See the policy.yaml example file for
// the full configuration schema.
package passguard
