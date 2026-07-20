package errs

type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

func New(
	code Code,
	message string,
) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}
