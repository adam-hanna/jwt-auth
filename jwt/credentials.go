package jwt

import (
	"errors"
	"log"
	"time"

	"github.com/adam-hanna/randomstrings"
	jwtGo "github.com/dgrijalva/jwt-go"
)

type credentials struct {
	CsrfString string

	AuthToken    jwtToken
	RefreshToken jwtToken

	options credentialsOptions
}

type credentialsOptions struct {
	AuthTokenValidTime    time.Duration
	RefreshTokenValidTime time.Duration

	CheckTokenId TokenIdChecker

	SigningMethodString string

	VerifyOnlyServer bool

	Debug bool
}

func (c *credentials) myLog(stoofs interface{}) {
	if c.options.Debug {
		log.Println(stoofs)
	}
}

func (a *Auth) buildCredentialsFromClaims(c *credentials, claims *ClaimsType) *jwtError {
	newCsrfString, err := generateNewCsrfString()
	if err != nil {
		return newJwtError(err, 500)
	}
	c.CsrfString = newCsrfString

	c.options.AuthTokenValidTime = a.options.AuthTokenValidTime
	c.options.RefreshTokenValidTime = a.options.RefreshTokenValidTime
	c.options.CheckTokenId = a.checkTokenId
	c.options.VerifyOnlyServer = a.options.VerifyOnlyServer
	c.options.SigningMethodString = a.options.SigningMethodString
	c.options.Debug = a.options.Debug

	authClaims := *claims
	authClaims.Csrf = newCsrfString
	authClaims.StandardClaims.ExpiresAt = time.Now().Add(a.options.AuthTokenValidTime).Unix()
	c.AuthToken = *c.newTokenWithClaims(authClaims, a.options.AuthTokenValidTime)

	refreshClaimsClaims := *claims
	refreshClaimsClaims.Csrf = newCsrfString
	refreshClaimsClaims.StandardClaims.ExpiresAt = time.Now().Add(a.options.RefreshTokenValidTime).Unix()
	c.RefreshToken = *c.newTokenWithClaims(refreshClaimsClaims, a.options.RefreshTokenValidTime)

	return nil
}

func (a *Auth) buildCredentialsFromStrings(csrfString string, authTokenString string, refreshTokenString string, c *credentials) *jwtError {
	// check inputs
	if csrfString == "" || authTokenString == "" || refreshTokenString == "" {
		return newJwtError(errors.New("Invalid inputs to build credentials. Inputs cannot be blank"), 401)
	}

	// inputs are good
	c.CsrfString = csrfString

	c.options.AuthTokenValidTime = a.options.AuthTokenValidTime
	c.options.RefreshTokenValidTime = a.options.RefreshTokenValidTime
	c.options.CheckTokenId = a.checkTokenId
	c.options.VerifyOnlyServer = a.options.VerifyOnlyServer
	c.options.SigningMethodString = a.options.SigningMethodString
	c.options.Debug = a.options.Debug

	// Note: Don't check for errors because it will be done later
	//       Also, tokens that have expired will throw err?
	c.AuthToken = *c.buildTokenWithClaimsFromString(authTokenString, a.verifyKey, a.options.AuthTokenValidTime)

	c.RefreshToken = *c.buildTokenWithClaimsFromString(refreshTokenString, a.verifyKey, a.options.RefreshTokenValidTime)

	return nil
}

func (c *credentials) validateCsrfStringAgainstCredentials() *jwtError {
	authTokenClaims, ok := c.AuthToken.Token.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}
	// note @adam-hanna: check csrf in refresh token?
	// refreshTokenClaims, ok := c.RefreshToken.Claims.(*ClaimsType)
	// if !ok {
	// 	return newJwtError(errors.New("Cannot read token claims"), 500)
	// }
	if c.CsrfString != authTokenClaims.Csrf {
		return newJwtError(errors.New("CSRF token doesn't match value in jwts"), 401)
	}

	return nil
}

func generateNewCsrfString() (string, error) {
	// note @adam-hanna: allow user's to set length?
	return randomstrings.GenerateRandomString(32)
}

func (c *credentials) updateAuthTokenFromRefreshToken() *jwtError {
	refreshTokenClaims, ok := c.RefreshToken.Token.Claims.(*ClaimsType)
	if !ok {
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}

	// check if the refresh token has been revoked
	if c.options.CheckTokenId(refreshTokenClaims.StandardClaims.Id) {
		c.myLog("Refresh token has not been revoked")
		// has it expired?
		if c.RefreshToken.Token.Valid {
			c.myLog("Refresh token is not expired")
			// nope, the refresh token has not expired
			// issue a new tokens with a new csrf and update all expiries
			newCsrfString, err := generateNewCsrfString()
			if err != nil {
				return newJwtError(err, 500)
			}

			c.CsrfString = newCsrfString

			err = c.AuthToken.updateTokenExpiryAndCsrf(newCsrfString)
			if err != nil {
				return newJwtError(err, 500)
			}

			return c.RefreshToken.updateTokenExpiryAndCsrf(newCsrfString)
		} else {
			c.myLog("Refresh token is invalid")
			return newJwtError(errors.New("Refresh token is invalid. Cannot refresh auth token."), 401)
		}
	} else {
		c.myLog("Refresh token has been revoked")
		return newJwtError(errors.New("Refresh token has been revoked. Cannot update auth token"), 401)
	}
}

func (c *credentials) validateAndUpdateCredentials() *jwtError {
	// first, check that the csrf token matches what's in the jwts
	err := c.validateCsrfStringAgainstCredentials()
	if err != nil {
		return newJwtError(err, 500)
	}

	// next, check the auth token in a stateless manner
	if c.AuthToken.Token.Valid {
		// auth token has not expired and is valid
		c.myLog("Auth token has not expired and is valid")

		// If this server is allowed to issue new tokens...
		// create a new csrf string and update the expiration time of the refresh token.
		// We don't want to update the auth expiry here bc that would necessitate checking the...
		// validity of the refresh token (which requires a db lookup, and hence isn't statelss)
		if !c.options.VerifyOnlyServer {
			newCsrfString, err := generateNewCsrfString()
			if err != nil {
				return newJwtError(err, 500)
			}

			c.CsrfString = newCsrfString

			err = c.AuthToken.updateTokenCsrf(newCsrfString)
			if err != nil {
				return newJwtError(err, 500)
			}

			return c.RefreshToken.updateTokenExpiryAndCsrf(newCsrfString)
		}
		return nil
	} else if ve, ok := c.AuthToken.ParseErr.(*jwtGo.ValidationError); ok {
		c.myLog("Auth token is not valid")
		if ve.Errors&(jwtGo.ValidationErrorExpired) != 0 {
			c.myLog("Auth token is expired")
			if !c.options.VerifyOnlyServer {
				// attemp to update the tokens
				return c.updateAuthTokenFromRefreshToken()
			}

			c.myLog("Auth token is expired and server is not authorized to issue new tokens")
			return newJwtError(errors.New("Auth token is expired and server is not authorized to issue new tokens"), 401)
		} else {
			c.myLog("Error in auth token")
			return newJwtError(errors.New("Auth token is not valid, and not because it has expired"), 401)
		}
	} else {
		c.myLog("Error in auth token")
		return newJwtError(errors.New("Auth token is not valid, and not because it has expired"), 401)
	}
}
