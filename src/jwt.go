// much of the architecture for this package was taken from https://github.com/unrolled/secure
// thanks!

package jwt

import (
	"net/http"
	"crypto/rsa"
	"io/ioutil"
	"time"
	"errors"
	// "log"
	"github.com/adam-hanna/randomstrings"
	jwt "github.com/dgrijalva/jwt-go"
)

type ClaimsType struct {
	// Standard claims are the standard jwt claims from the ietf standard
	// https://tools.ietf.org/html/rfc7519
	jwt.StandardClaims
	Csrf 				string
	CustomClaims 		map[string]interface{}
}

// Options is a struct for specifying configuration options
type Options struct {
	PrivateKeyLocation 		string
	PublicKeyLocation 		string
	RefreshTokenValidTime 	time.Duration
	AuthTokenValidTime 		time.Duration
	TokenClaims 			ClaimsType
}

const defaultRefreshTokenValidTime 	= 72 * time.Hour
const defaultAuthTokenValidTime 	= 15 * time.Minute

func defaultTokenRevoker(tokenId string) error {
	return nil
}

type TokenRevoker func(tokenId string) error

func defaultCheckTokenId(tokenId string) bool {
	// return true if the token id is valid (has not been revoked). False for otherwise
	return true
}

type TokenIdChecker func(tokenId string) bool

func defaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", 500)
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unauthorized", 401)
}

// Auth is a middleware that provides jwt based authentication.
type Auth struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey

	options Options

	// Handlers for when an error occurs
	errorHandler 			http.Handler
	unauthorizedHandler 	http.Handler

	// funcs for certain actions
	revokeRefreshToken 	TokenRevoker
	checkTokenId 		TokenIdChecker
}

// New constructs a new Auth instance with supplied options.
func New(auth *Auth, options ...Options) (error) {
	var o Options
	if len(options) == 0 {
		o = Options{}
	} else {
		o = options[0]
	}

	// check to make sure the provided options are valid
	if o.PrivateKeyLocation == "" || o.PublicKeyLocation == "" {
		return errors.New("Private and public key locations are required!")
	}

	// check if durations have been provided for auth and refresh token exp
	// if not, set them equal to the default
	if o.RefreshTokenValidTime <= 0 {
		// log.Println("Using default refreh token time")
		o.RefreshTokenValidTime = defaultRefreshTokenValidTime
	}
	if o.AuthTokenValidTime <= 0 {
		// log.Println("Using default auth token time")
		o.AuthTokenValidTime = defaultAuthTokenValidTime
	}

	// read the key files
	signBytes, err := ioutil.ReadFile(o.PrivateKeyLocation)
	if err != nil {
		return err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(o.PublicKeyLocation)
	if err != nil {
		return err
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	auth.signKey 				= signKey
	auth.verifyKey 				= verifyKey
	auth.options 				= o
	auth.errorHandler 			= http.HandlerFunc(defaultErrorHandler)
	auth.unauthorizedHandler 	= http.HandlerFunc(defaultUnauthorizedHandler)
	auth.revokeRefreshToken 	= TokenRevoker(defaultTokenRevoker)
	auth.checkTokenId 			= TokenIdChecker(defaultCheckTokenId)

	return nil
}


// add methods to allow the changing of default functions
func (a *Auth) SetErrorHandler(handler http.Handler) {
	a.errorHandler = handler
}
func (a *Auth) SetUnauthorizedHandler(handler http.Handler) {
	a.unauthorizedHandler = handler
}
func (a *Auth) SetRevokeTokenFunction(revoker TokenRevoker) {
	a.revokeRefreshToken = revoker
}
func (a *Auth) SetCheckTokenIdFunction(checker TokenIdChecker) {
	a.checkTokenId = checker
}

// Handler implements the http.HandlerFunc for integration with the standard net/http lib.
func (a *Auth) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		err := a.Process(w, r)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

// HandlerFuncWithNext is a special implementation for Negroni, but could be used elsewhere.
func (a *Auth) HandlerFuncWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	err := a.Process(w, r)

	// If there was an error, do not call next.
	if err == nil && next != nil {
		next(w, r)
	}
}

// Process runs the actual checks and returns an error if the middleware chain should stop.
func (a *Auth) Process(w http.ResponseWriter, r *http.Request) error {
	// read cookies
	AuthCookie, authErr := r.Cookie("AuthToken")
	if authErr == http.ErrNoCookie {
		// log.Println("Unauthorized attempt! No auth cookie")
		a.NullifyTokenCookies(&w, r)
		a.unauthorizedHandler.ServeHTTP(w, r)
		return errors.New("Unauthorized")
	} else if authErr != nil {
		// log.Panic("panic: %+v", authErr)
		a.NullifyTokenCookies(&w, r)
		a.errorHandler.ServeHTTP(w, r)
		return errors.New("Internal Server Error")
	}

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		// log.Println("Unauthorized attempt! No refresh cookie")
		a.NullifyTokenCookies(&w, r)
		a.unauthorizedHandler.ServeHTTP(w, r)
		return errors.New("Unauthorized")
	} else if refreshErr != nil {
		// log.Panic("panic: %+v", refreshErr)
		a.NullifyTokenCookies(&w, r)
		a.errorHandler.ServeHTTP(w, r)
		return errors.New("Internal Server Error")
	}

	// grab the csrf token
	requestCsrfToken := grabCsrfFromReq(r)

	// check the jwt's for validity
	authTokenString, refreshTokenString, csrfSecret, err := a.checkAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
	if err != nil {
		if err.Error() == "Unauthorized" {
			// log.Println("Unauthorized attempt! JWT's not valid!")

			a.unauthorizedHandler.ServeHTTP(w, r)
			return errors.New("Unauthorized")
		} else {
			// @adam-hanna: do we 401 or 500, here?
			// it could be 401 bc the token they provided was messed up
			// or it could be 500 bc there was some error on our end
			// log.Println("err not nil")
			// log.Panic("panic: %+v", err)
			a.errorHandler.ServeHTTP(w, r)
			return errors.New("Internal Server Error")
		}
	}

	// log.Println("Successfully recreated jwts")
	// if we've made it this far, everything is valid!
	// And tokens have been refreshed if need-be
	setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
	w.Header().Set("X-CSRF-Token", csrfSecret)

	return nil
}

func (a *Auth) NullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: "",
		Expires: time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: "",
		Expires: time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)

	// if present, revoke the refresh cookie from our db
	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		// do nothing, there is no refresh cookie present
		return
	} else if refreshErr != nil {
		// log.Panic("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	} else {
		a.revokeRefreshToken(RefreshCookie.Value)
	}

	return
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: authTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromFrom := r.FormValue("X-CSRF-Token")

	if csrfFromFrom != "" {
		return csrfFromFrom
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}

// and also modify create refresh and auth token functions!
func (a *Auth) IssueNewTokens(w http.ResponseWriter, claims ClaimsType) (err error) {
	// generate the csrf secret
	csrfSecret, err := randomstrings.GenerateRandomString(32)
	if err != nil {
		return
	}
	w.Header().Set("X-CSRF-Token", csrfSecret)

	// generate the refresh token
	refreshTokenString, err := a.createRefreshTokenString(claims, csrfSecret)

	// generate the auth token
	authTokenString, err := a.createAuthTokenString(claims, csrfSecret)
	if err != nil {
		return
	}

	setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
	// don't need to check for err bc we're returning everything anyway
	return
}

// @adam-hanna: check if refreshToken["sub"] == authToken["sub"]?
// I don't think this is necessary bc a valid refresh token will always generate
// a valid auth token of the same "sub"
func (a *Auth) checkAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {
	// first, check that a csrf token was provided
	if oldCsrfSecret == "" {
		// log.Println("No CSRF token!")
		err = errors.New("Unauthorized")
		return
	}

	// now, check that it matches what's in the auth token claims
	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &ClaimsType{}, func(token *jwt.Token) (interface{}, error) {
		return a.verifyKey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*ClaimsType)
	if !ok {
		return
	}
	if oldCsrfSecret != authTokenClaims.Csrf {
		// log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return
	}


	// next, check the auth token in a stateless manner
	if authToken.Valid {
		// log.Println("Auth token is valid")
		// auth token has not expired
		// we need to return the csrf secret bc that's what the function calls for
		newCsrfSecret = authTokenClaims.Csrf

		// update the exp of refresh token string, but don't save to the db
		// we don't need to check if our refresh token is valid here
		// because we aren't renewing the auth token, the auth token is already valid
		newRefreshTokenString, err = a.updateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString
		return
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		// log.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			// log.Println("Auth token is expired")
			// auth token is expired
			// fyi - refresh token is checked in the update auth func
			newAuthTokenString, newCsrfSecret, err = a.updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
			if err != nil {
				return
			}

			// update the exp of refresh token string
			newRefreshTokenString, err = a.updateRefreshTokenExp(oldRefreshTokenString)
			if err != nil {
				return
			}

			// update the csrf string of the refresh token
			newRefreshTokenString, err = a.updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			return
		} else {
			// log.Println("Error in auth token")
			err = errors.New("Error in auth token")
			return
		}
	} else {
		// log.Println("Error in auth token")
		err = errors.New("Error in auth token")
		return
	}
}

func (a *Auth) createRefreshTokenString(claims ClaimsType, csrfString string) (refreshTokenString string, err error) {
	refreshTokenExp := time.Now().Add(a.options.RefreshTokenValidTime).Unix()
	if err != nil {
		return
	}

	claims.StandardClaims.ExpiresAt = refreshTokenExp
	claims.Csrf = csrfString

	// create a signer for rsa 256
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

	// generate the refresh token string
	refreshTokenString, err = refreshJwt.SignedString(a.signKey)
	return
}

func (a *Auth) createAuthTokenString(claims ClaimsType, csrfSecret string) (authTokenString string, err error) {
	authTokenExp := time.Now().Add(a.options.AuthTokenValidTime).Unix()
	
	claims.StandardClaims.ExpiresAt = authTokenExp
	claims.Csrf = csrfSecret

	// create a signer for rsa 256
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

	// generate the auth token string
	authTokenString, err = authJwt.SignedString(a.signKey)
	return
}

func (a *Auth) updateRefreshTokenExp(oldRefreshTokenString string) (string, error) {
	refreshToken, _ := jwt.ParseWithClaims(oldRefreshTokenString, &ClaimsType{}, func(token *jwt.Token) (interface{}, error) {
        return a.verifyKey, nil
    })

    oldRefreshTokenClaims, ok := refreshToken.Claims.(*ClaimsType)
    if !ok {
		return "", errors.New("Error parsing claims")
	}

	refreshTokenExp := time.Now().Add(a.options.RefreshTokenValidTime).Unix()
	oldRefreshTokenClaims.StandardClaims.ExpiresAt = refreshTokenExp

	// create a signer for rsa 256
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), oldRefreshTokenClaims)

	// generate the refresh token string
	return refreshJwt.SignedString(a.signKey)
}

func (a *Auth) updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &ClaimsType{}, func(token *jwt.Token) (interface{}, error) {
		return a.verifyKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*ClaimsType)
	if !ok {
		err = errors.New("Error reading jwt claims")
		return
	}

	// check if the refresh token has been revoked
	if a.checkTokenId(refreshTokenClaims.StandardClaims.Id) {
		// log.Println("Refresh token has not been revoked")
		// the refresh token has not been revoked
		// has it expired?
		if refreshToken.Valid {
			// log.Println("Refresh token is not expired")
			// nope, the refresh token has not expired
			// issue a new auth token

			// our policy is to regenerate the csrf secret for each new auth token
			csrfSecret, err = randomstrings.GenerateRandomString(32)
			if err != nil {
				return
			}

			newAuthTokenString, err = a.createAuthTokenString(*refreshTokenClaims, csrfSecret)
			
			// fyi - updating of refreshtoken csrf and exp is done after calling this func
			// so we can simply return
			return
		} else {
			// log.Println("Refresh token has expired!")
			// the refresh token has expired! Require the user to re-authenticate
			// @adam-hanna: Do we want to revoke the token in our db?
			// I don't think we need to because it has expired and we can simply check the 
			// exp. No need to update the db.

			err = errors.New("Unauthorized")
			return
		}
	} else {
		// log.Println("Refresh token has been revoked!")
		// the refresh token has been revoked!
		err = errors.New("Unauthorized")
		return
	}
}

func (a *Auth) updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string) (string, error) {
	refreshToken, _ := jwt.ParseWithClaims(oldRefreshTokenString, &ClaimsType{}, func(token *jwt.Token) (interface{}, error) {
        return a.verifyKey, nil
    })

    oldRefreshTokenClaims, ok := refreshToken.Claims.(*ClaimsType)
    if !ok {
		return "", errors.New("Error parsing claims")
	}

	oldRefreshTokenClaims.Csrf = newCsrfString

	// create a signer for rsa 256
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), oldRefreshTokenClaims)

	// generate the refresh token string
	return refreshJwt.SignedString(a.signKey)
}

func (a *Auth) GrabTokenClaims(w http.ResponseWriter, r *http.Request) (ClaimsType, error) {
	// read cookies
	AuthCookie, authErr := r.Cookie("AuthToken")
	if authErr == http.ErrNoCookie {
		// log.Println("Unauthorized attempt! No auth cookie")
		a.NullifyTokenCookies(&w, r)
		a.unauthorizedHandler.ServeHTTP(w, r)
		return ClaimsType{}, errors.New("Unauthorized")
	} else if authErr != nil {
		// log.Panic("panic: %+v", authErr)
		a.NullifyTokenCookies(&w, r)
		a.errorHandler.ServeHTTP(w, r)
		return ClaimsType{}, errors.New("Unauthorized")
	}
	
	token, _ := jwt.ParseWithClaims(AuthCookie.Value, &ClaimsType{}, func(token *jwt.Token) (interface{}, error) {
		return ClaimsType{}, errors.New("Error processing token string claims")
	})
	tokenClaims, ok := token.Claims.(*ClaimsType) 
	if !ok {
		return ClaimsType{}, errors.New("Error processing token string claims")
	}

	return *tokenClaims, nil
}
