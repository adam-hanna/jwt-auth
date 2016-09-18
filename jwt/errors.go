package jwt

import (
	"reflect"
)

// Helper for constructing a ValidationError with a string error message
func newJwtError(err interface{}, errType int) *jwtError {
	var j jwtError

	// passthrough if this is already a pointer to a jwtErr
	if reflect.TypeOf(err) == reflect.TypeOf(&j) {
		return err.(*jwtError)
	}

	return &jwtError{
		Inner: err.(error),
		Type:  errType,
	}
}

// A special error that tracks what http return code should be sent to client
type jwtError struct {
	Inner error // stores the actual error
	Type  int   // Either a 4xx unauthorized or 5xx internal server err
}

func (e jwtError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	}
	return "Unknown error"
}
