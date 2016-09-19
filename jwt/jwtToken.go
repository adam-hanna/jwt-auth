package jwt

import (
	"errors"
	"time"

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

func (a *Auth) updateTokenExpiry(token *jwtToken, expiry time.Duration) *jwtError {
	tokenClaims, ok := token.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}

	tokenClaims.StandardClaims.ExpiresAt = time.Now().Add(expiry).Unix()

	// update the token
	token = newWithClaims(jwtGo.GetSigningMethod(a.options.SigningMethodString), tokenClaims)

	return nil
}

func (a *Auth) updateTokenCsrf(token *jwtToken, csrfString string) *jwtError {
	tokenClaims, ok := token.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}

	tokenClaims.Csrf = csrfString

	// update the token
	token = newWithClaims(jwtGo.GetSigningMethod(a.options.SigningMethodString), tokenClaims)

	return nil
}

func (a *Auth) updateTokenExpiryAndCsrf(token *jwtToken, expiry time.Duration, csrfString string) *jwtError {
	tokenClaims, ok := token.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}

	tokenClaims.StandardClaims.ExpiresAt = time.Now().Add(expiry).Unix()
	tokenClaims.Csrf = csrfString

	// update the token
	token = newWithClaims(jwtGo.GetSigningMethod(a.options.SigningMethodString), tokenClaims)

	return nil
}
