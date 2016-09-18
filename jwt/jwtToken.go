package jwt

import (
	"errors"

	jwtGo "github.com/dgrijalva/jwt-go"
)

type jwtToken struct {
	jwtGo.Token
}

func (a *Auth) buildTokenWithClaimsFromString(tokenString string) (*jwtToken, error) {
	token, err := jwtGo.ParseWithClaims(tokenString, &ClaimsType{}, func(token *jwtGo.Token) (interface{}, error) {
		if token.Method != jwtGo.GetSigningMethod(a.options.SigningMethodString) {
			a.myLog("Incorrect singing method on token")
			return nil, errors.New("Incorrect singing method on token")
		}
		return a.verifyKey, nil
	})

	return &jwtToken{*token}, err
}

func newWithClaims(method jwtGo.SigningMethod, claims jwtGo.Claims) *jwtToken {
	return &jwtToken{*jwtGo.NewWithClaims(method, claims)}
}
