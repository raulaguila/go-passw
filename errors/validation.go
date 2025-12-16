package errors

type ValidationError struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *ValidationError) Error() string {
	return e.Message
}

func (e *ValidationError) WithDetails(details map[string]any) *ValidationError {
	return &ValidationError{
		Code:    e.Code,
		Message: e.Message,
		Details: details,
	}
}

func New(code, msg string) *ValidationError {
	return &ValidationError{Code: code, Message: msg}
}
