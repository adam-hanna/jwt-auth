package jwt

import (
	"errors"
	"testing"
)

func Test_Errors(t *testing.T) {
	s := "Testing Err"
	errT := 500
	myErr := newJwtError(errors.New(s), errT)

	if myErr.Error() != s {
		t.Errorf("[%s != %s] Error strings do not match", myErr.Error(), s)
	}

	if myErr.Type != errT {
		t.Errorf("[%d != %d] Error types do not match", myErr.Type, errT)
	}

	errT2 := 401
	myErr2 := newJwtError(myErr, errT2)

	if myErr2.Error() != s {
		t.Errorf("[%s != %s] Error strings to not match", myErr2.Error(), s)
	}

	if myErr2.Type != errT {
		t.Errorf("[%d != %d] Error types do not match", myErr2.Type, errT)
	}
}
