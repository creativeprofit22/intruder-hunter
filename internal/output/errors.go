package output

import "fmt"

const (
	CodeCommandFailed      = "IH_COMMAND_FAILED"
	CodeUnsupportedFormat  = "IH_UNSUPPORTED_OUTPUT_FORMAT"
	CodeScanNotImplemented = "IH_SCAN_NOT_IMPLEMENTED"
	CodeDoctorStub         = "IH_DOCTOR_STUB"
)

type Error struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Details  string `json:"details,omitempty"`
	Rendered bool   `json:"-"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}

	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewError(code, message, details string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Details: details,
	}
}

func MarkRendered(err *Error) *Error {
	if err != nil {
		err.Rendered = true
	}
	return err
}

func NormalizeError(err error) *Error {
	if err == nil {
		return nil
	}

	if outputErr, ok := err.(*Error); ok {
		return outputErr
	}

	return NewError(CodeCommandFailed, err.Error(), "")
}
