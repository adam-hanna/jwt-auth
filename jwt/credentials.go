package jwt

import (
	"errors"
	"net/http"
	"time"

	"github.com/adam-hanna/randomstrings"
	jwtGo "github.com/dgrijalva/jwt-go"
)

type credentials struct {
	CsrfString string

	AuthToken                   jwtToken
	AuthTokenParseWithClaimsErr error

	RefreshToken                   jwtToken
	RefreshTokenParseWithClaimsErr error
}

func (a *Auth) buildCredentialsFromScratch(c *credentials, claims ClaimsType) *jwtError {
	newCsrfString, err := generateNewCsrfString()
	if err != nil {
		return newJwtError(err, 500)
	}
	c.CsrfString = newCsrfString
	claims.Csrf = newCsrfString

	claims.StandardClaims.ExpiresAt = time.Now().Add(a.options.AuthTokenValidTime).Unix()
	c.AuthToken = *newWithClaims(jwtGo.GetSigningMethod(a.options.SigningMethodString), claims)

	claims.StandardClaims.ExpiresAt = time.Now().Add(a.options.RefreshTokenValidTime).Unix()
	c.RefreshToken = *newWithClaims(jwtGo.GetSigningMethod(a.options.SigningMethodString), claims)

	return nil
}

func (a *Auth) buildCredentialsFromRequest(r *http.Request, c *credentials) *jwtError {
	authTokenString, refreshTokenString, err := a.extractTokenStringsFromReq(r)
	if err != nil {
		return newJwtError(err, 500)
	}

	csrfString, err := extractCsrfStringFromReq(r)
	if err != nil {
		return newJwtError(err, 500)
	}

	return a.buildCredentialsFromStrings(csrfString, authTokenString, refreshTokenString, c)
}

func (a *Auth) buildCredentialsFromStrings(csrfString string, authTokenString string, refreshTokenString string, c *credentials) *jwtError {
	// check inputs
	if csrfString == "" || authTokenString == "" || refreshTokenString == "" {
		return newJwtError(errors.New("Invalid inputs to build credentials. Inputs cannot be blank"), 401)
	}

	// inputs are good
	c.CsrfString = csrfString

	// Note: Don't check for errors because it will be done later
	//       Also, tokens that have expired will throw err?
	tempAuthToken, tempAuthParseErr := a.buildTokenWithClaimsFromString(authTokenString)
	c.AuthToken = *tempAuthToken
	c.AuthTokenParseWithClaimsErr = tempAuthParseErr

	tempRefreshToken, tempRefreshParseErr := a.buildTokenWithClaimsFromString(refreshTokenString)
	c.RefreshToken = *tempRefreshToken
	c.RefreshTokenParseWithClaimsErr = tempRefreshParseErr

	return nil
}

func validateCsrfStringAgainstCredentials(c *credentials) *jwtError {
	authTokenClaims, ok := c.AuthToken.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}
	refreshTokenClaims, ok := c.RefreshToken.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}
	if c.CsrfString != authTokenClaims.Csrf || c.CsrfString != refreshTokenClaims.Csrf {
		return newJwtError(errors.New("CSRF token doesn't match value in jwts!"), 401)
	}

	return nil
}

func generateNewCsrfString() (string, error) {
	// note @adam-hanna: allow user's to set length?
	return randomstrings.GenerateRandomString(32)
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

func (a *Auth) updateAuthTokenFromRefreshToken(c *credentials) *jwtError {
	refreshTokenClaims, ok := c.RefreshToken.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}

	// check if the refresh token has been revoked
	if a.checkTokenId(refreshTokenClaims.StandardClaims.Id) {
		a.myLog("Refresh token has not been revoked")
		// has it expired?
		if c.RefreshToken.Valid {
			a.myLog("Refresh token is not expired")
			// nope, the refresh token has not expired
			// issue a new tokens with a new csrf and update all expiries
			newCsrfString, err := generateNewCsrfString()
			if err != nil {
				return newJwtError(err, 500)
			}

			err = a.updateTokenExpiryAndCsrf(&c.AuthToken, a.options.AuthTokenValidTime, newCsrfString)
			if err != nil {
				return newJwtError(err, 500)
			}

			return a.updateTokenExpiryAndCsrf(&c.RefreshToken, a.options.RefreshTokenValidTime, newCsrfString)
		} else {
			a.myLog("Refresh token has expired!")
			return newJwtError(errors.New("Refresh token has expired. Cannot refresh auth token."), 401)
		}
	} else {
		a.myLog("Refresh token has been revoked!")
		return newJwtError(errors.New("Refresh token has been revoked. Cannot update auth token"), 401)
	}
}

func (a *Auth) validateAndUpdateCredentials(c *credentials) *jwtError {
	// first, check that the csrf token matches what's in the jwts
	err := validateCsrfStringAgainstCredentials(c)
	if err != nil {
		return newJwtError(err, 500)
	}

	// next, check the auth token in a stateless manner
	if c.AuthToken.Valid {
		// auth token has not expired and is valid
		a.myLog("Auth token has not expired and is valid")

		// If this server is allowed to issue new tokens...
		// create a new csrf string and update the expiration time of the refresh token.
		// We don't want to update the auth expiry here bc that would necessitate checking the...
		// validity of the refresh token (which requires a db lookup, and hence isn't statelss)
		if !a.options.VerifyOnlyServer {
			newCsrfString, err := generateNewCsrfString()
			if err != nil {
				return newJwtError(err, 500)
			}

			return a.updateTokenExpiryAndCsrf(&c.RefreshToken, a.options.RefreshTokenValidTime, newCsrfString)
		}
		return nil
	} else if ve, ok := c.RefreshTokenParseWithClaimsErr.(*jwtGo.ValidationError); ok {
		a.myLog("Auth token is not valid")
		if ve.Errors&(jwtGo.ValidationErrorExpired) != 0 {
			a.myLog("Auth token is expired")
			if a.options.VerifyOnlyServer {
				a.myLog("Auth token is expired and server is not authorized to issue new tokens")
				return newJwtError(errors.New("Auth token is expired and server is not authorized to issue new tokens"), 401)
			} else {
				// attemp to update the tokens
				return a.updateAuthTokenFromRefreshToken(c)
			}
		} else {
			a.myLog("Error in auth token")
			return newJwtError(errors.New("Auth token is not valid, and not because it has expired"), 401)
		}
	} else {
		a.myLog("Error in auth token")
		return newJwtError(errors.New("Auth token is not valid, and not because it has expired"), 401)
	}
}
