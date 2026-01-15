// Package errors defines validation error types for the password validation library.
package errors

// ValidationError represents a password validation failure.
// It contains a machine-readable code, human-readable message, and optional details.
type ValidationError struct {
	// Code is a machine-readable identifier for the error type.
	// Examples: "LENGTH_TOO_SHORT", "LOW_ENTROPY", "SEQUENCE_TOO_LONG"
	Code string `json:"code"`

	// Message is a human-readable description of the error.
	Message string `json:"message"`

	// Details contains additional context about the validation failure.
	// The keys and values depend on the specific error code.
	Details map[string]any `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return e.Message
}

// WithDetails returns a new ValidationError with the given details.
// This method is useful for adding context to error messages.
func (e *ValidationError) WithDetails(details map[string]any) *ValidationError {
	return &ValidationError{
		Code:    e.Code,
		Message: e.Message,
		Details: details,
	}
}

// New creates a new ValidationError with the given code and message.
func New(code, msg string) *ValidationError {
	return &ValidationError{Code: code, Message: msg}
}
