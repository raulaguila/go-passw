package errors

type ValidationError struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *ValidationError) Error() string {
	return e.Message
}

func New(code, msg string) *ValidationError {
	return &ValidationError{Code: code, Message: msg}
}
