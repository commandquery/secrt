package jtp

import (
	"fmt"
	"net/http"
)

var (
	ErrBadRequest          = BadRequestError(nil)
	ErrNotFound            = NotFoundError(nil)
	ErrInternalServerError = InternalServerError(nil)
	ErrForbidden           = ForbiddenError(nil)
	ErrUnauthorized        = UnauthorizedError(nil)
	ErrConflict            = ConflictError(nil)
	ErrNoContent           = NoContentError()
)

type HTTPError struct {
	StatusCode int
	Err        error
}

func (e *HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("Error: %s (http status %d)", e.Err.Error(), e.StatusCode)
	}
	return fmt.Sprintf("HTTP status %d", e.StatusCode)
}

func (e *HTTPError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is enables us to look for http errors by status code.
// For example, you can do: errors.Is(err, *HTTPError{StatusCode: http.StatusNotFound})
// Some error codes are predefined: errors.Is(err, NotFoundError) will also work.
func (e *HTTPError) Is(target error) bool {
	if t, ok := target.(*HTTPError); ok {
		return e.StatusCode == t.StatusCode
	}
	return false
}

func BadRequestError(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusBadRequest,
		Err:        err,
	}
}

func NotFoundError(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusNotFound,
		Err:        err,
	}
}

func InternalServerError(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

func ForbiddenError(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusForbidden,
		Err:        err,
	}
}

func UnauthorizedError(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusUnauthorized,
		Err:        err,
	}
}

func ConflictError(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusConflict,
		Err:        err,
	}
}

func NoContentError() *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusNoContent,
		Err:        nil,
	}
}
