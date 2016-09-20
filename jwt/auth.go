package jwt

import (
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"time"

	jwtGo "github.com/dgrijalva/jwt-go"
)

// Auth is a middleware that provides jwt based authentication.
type Auth struct {
	signKey   interface{}
	verifyKey interface{}

	options Options

	// Handlers for when an error occurs
	errorHandler        http.Handler
	unauthorizedHandler http.Handler

	// funcs for checking and revoking refresh tokens
	revokeRefreshToken TokenRevoker
	checkTokenId       TokenIdChecker
}

// Options is a struct for specifying configuration options
type Options struct {
	SigningMethodString   string
	PrivateKeyLocation    string
	PublicKeyLocation     string
	HMACKey               []byte
	VerifyOnlyServer      bool
	BearerTokens          bool
	RefreshTokenValidTime time.Duration
	AuthTokenValidTime    time.Duration
	Debug                 bool
	IsDevEnv              bool
}

const defaultRefreshTokenValidTime = 72 * time.Hour
const defaultAuthTokenValidTime = 15 * time.Minute

type ClaimsType struct {
	// Standard claims are the standard jwt claims from the ietf standard
	// https://tools.ietf.org/html/rfc7519
	jwtGo.StandardClaims
	Csrf         string
	CustomClaims map[string]interface{}
}

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
	return
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unauthorized", 401)
	return
}

// this is a general json struct for when bearer tokens are used
type bearerTokensStruct struct {
	Auth_Token    string `json: "Auth_Token"`
	Refresh_Token string `json: "Refresh_Token"`
}

// New constructs a new Auth instance with supplied options.
func New(auth *Auth, options ...Options) error {
	var o Options
	if len(options) == 0 {
		o = Options{}
	} else {
		o = options[0]
	}

	// check if durations have been provided for auth and refresh token exp
	// if not, set them equal to the default
	if o.RefreshTokenValidTime <= 0 {
		o.RefreshTokenValidTime = defaultRefreshTokenValidTime
	}
	if o.AuthTokenValidTime <= 0 {
		o.AuthTokenValidTime = defaultAuthTokenValidTime
	}

	// create the sign and verify keys
	var signKey interface{}
	var verifyKey interface{}
	if o.SigningMethodString == "HS256" || o.SigningMethodString == "HS384" || o.SigningMethodString == "HS512" {
		if len(o.HMACKey) == 0 {
			return errors.New("When using an HMAC-SHA signing method, please provide an HMACKey")
		}
		if !o.VerifyOnlyServer {
			signKey = o.HMACKey
		}
		verifyKey = o.HMACKey

	} else if o.SigningMethodString == "RS256" || o.SigningMethodString == "RS384" || o.SigningMethodString == "RS512" {
		// check to make sure the provided options are valid
		if o.PrivateKeyLocation == "" && !o.VerifyOnlyServer {
			return errors.New("Private key location is required!")
		}
		if o.PublicKeyLocation == "" {
			return errors.New("Public key location is required!")
		}

		// read the key files
		if !o.VerifyOnlyServer {
			signBytes, err := ioutil.ReadFile(o.PrivateKeyLocation)
			if err != nil {
				return err
			}

			signKey, err = jwtGo.ParseRSAPrivateKeyFromPEM(signBytes)
			if err != nil {
				return err
			}
		}

		verifyBytes, err := ioutil.ReadFile(o.PublicKeyLocation)
		if err != nil {
			return err
		}

		verifyKey, err = jwtGo.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			return err
		}

	} else if o.SigningMethodString == "ES256" || o.SigningMethodString == "ES384" || o.SigningMethodString == "ES512" {
		// check to make sure the provided options are valid
		if o.PrivateKeyLocation == "" && !o.VerifyOnlyServer {
			return errors.New("Private key location is required!")
		}
		if o.PublicKeyLocation == "" {
			return errors.New("Public key location is required!")
		}

		// read the key files
		if !o.VerifyOnlyServer {
			signBytes, err := ioutil.ReadFile(o.PrivateKeyLocation)
			if err != nil {
				return err
			}

			signKey, err = jwtGo.ParseECPrivateKeyFromPEM(signBytes)
			if err != nil {
				return err
			}
		}

		verifyBytes, err := ioutil.ReadFile(o.PublicKeyLocation)
		if err != nil {
			return err
		}

		verifyKey, err = jwtGo.ParseECPublicKeyFromPEM(verifyBytes)
		if err != nil {
			return err
		}

	} else {
		return errors.New("Signing method string not recognized!")
	}

	auth.signKey = signKey
	auth.verifyKey = verifyKey
	auth.options = o
	auth.errorHandler = http.HandlerFunc(defaultErrorHandler)
	auth.unauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	auth.revokeRefreshToken = TokenRevoker(defaultTokenRevoker)
	auth.checkTokenId = TokenIdChecker(defaultCheckTokenId)

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
		// Process the request. If it returns an error,
		// that indicates the request should not continue.
		jwtErr := a.process(w, r)
		var j jwtError

		// If there was an error, do not continue.
		if jwtErr != nil {
			a.myLog("Error processing jwts\n" + jwtErr.Error())
			_ := a.NullifyTokens(&w, r)
			if reflect.TypeOf(jwtErr) == reflect.TypeOf(&j) && jwtErr.Type/100 == 4 {
				a.unauthorizedHandler.ServeHTTP(w, r)
				return
			} else {
				a.errorHandler.ServeHTTP(w, r)
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}

// HandlerFuncWithNext is a special implementation for Negroni, but could be used elsewhere.
func (a *Auth) HandlerFuncWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	jwtErr := a.process(w, r)
	var j jwtError

	// If there was an error, do not call next.
	if jwtErr == nil && next != nil {
		next(w, r)
	} else {
		a.myLog("Error processing jwts\n" + jwtErr.Error())
		_ := a.NullifyTokens(&w, r)
		if reflect.TypeOf(jwtErr) == reflect.TypeOf(&j) && jwtErr.Type/100 == 4 {
			a.unauthorizedHandler.ServeHTTP(w, r)
		} else {
			a.errorHandler.ServeHTTP(w, r)
		}
	}
}

// Process runs the actual checks and returns an error if the middleware chain should stop.
func (a *Auth) process(w http.ResponseWriter, r *http.Request) *jwtError {
	// cookies aren't included with options, so simply pass through
	if r.Method == "OPTIONS" {
		a.myLog("Method is OPTIONS")
		return nil
	}

	// grab the credentials from the request
	var c credentials
	err := a.buildCredentialsFromRequest(r, &c)
	if err != nil {
		return newJwtError(err, 500)
	}

	// check the credential's validity; updating expiry's if necessary and/or allowed
	err = c.validateAndUpdateCredentials()
	if err != nil {
		return newJwtError(err, 500)
	}

	a.myLog("Successfully checked / refreshed jwts")

	// if we've made it this far, everything is valid!
	// And tokens have been refreshed if need-be
	if !a.options.VerifyOnlyServer {
		err = a.setCredentialsOnResponseWriter(&w, &c)
		if err != nil {
			return newJwtError(err, 500)
		}
	}

	authTokenClaims, ok := c.AuthToken.Token.Claims.(*ClaimsType)
	if !ok {
		a.myLog("Cannot read auth token claims")
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}
	refreshTokenClaims, ok := c.RefreshToken.Token.Claims.(*ClaimsType)
	if !ok {
		a.myLog("Cannot read refresh token claims")
		return newJwtError(errors.New("Cannot read token claims"), 500)
	}

	w.Header().Set("X-CSRF-Token", c.CsrfString)
	// note @adam-hanna: this may not be correct when using a sep auth server?
	//    							 bc it checks the request?
	w.Header().Set("Auth-Expiry", strconv.FormatInt(authTokenClaims.StandardClaims.ExpiresAt, 10))
	w.Header().Set("Refresh-Expiry", strconv.FormatInt(refreshTokenClaims.StandardClaims.ExpiresAt, 10))

	return nil
}

// and also modify create refresh and auth token functions!
func (a *Auth) IssueNewTokens(w http.ResponseWriter, claims ClaimsType) error {
	if a.options.VerifyOnlyServer {
		a.myLog("Server is not authorized to issue new tokens")
		return errors.New("Server is not authorized to issue new tokens")

	} else {
		var c credentials
		err := a.buildCredentialsFromClaims(&c, &claims)
		if err != nil {
			return errors.New(err.Error())
		}

		err = a.setCredentialsOnResponseWriter(&w, &c)
		if err != nil {
			return errors.New(err.Error())
		}

		authTokenClaims, ok := c.AuthToken.Token.Claims.(ClaimsType)
		if !ok {
			a.myLog("Cannot read auth token claims")
			return newJwtError(errors.New("Cannot read token claims"), 500)
		}
		refreshTokenClaims, ok := c.RefreshToken.Token.Claims.(ClaimsType)
		if !ok {
			a.myLog("Cannot read refresh token claims")
			return newJwtError(errors.New("Cannot read token claims"), 500)
		}

		w.Header().Set("X-CSRF-Token", c.CsrfString)
		w.Header().Set("Auth-Expiry", strconv.FormatInt(authTokenClaims.StandardClaims.ExpiresAt, 10))
		w.Header().Set("Refresh-Expiry", strconv.FormatInt(refreshTokenClaims.StandardClaims.ExpiresAt, 10))

		return nil
	}
}

// note @adam-hanna: what if there are no credentials in the request?
func (a *Auth) NullifyTokens(w *http.ResponseWriter, r *http.Request) error {
	var c credentials
	err := a.buildCredentialsFromRequest(r, &c)
	if err != nil {
		a.myLog("Err building credentials\n" + err.Error())
		return errors.New(err.Error())
	}

	if a.options.BearerTokens {
		// tokens are not in cookies
		setHeader(*w, "Auth_Token", "")
		setHeader(*w, "Refresh_Token", "")
	} else {
		authCookie := http.Cookie{
			Name:     "AuthToken",
			Value:    "",
			Expires:  time.Now().Add(-1000 * time.Hour),
			HttpOnly: true,
			Secure:   !a.options.IsDevEnv,
		}

		http.SetCookie(*w, &authCookie)

		refreshCookie := http.Cookie{
			Name:     "RefreshToken",
			Value:    "",
			Expires:  time.Now().Add(-1000 * time.Hour),
			HttpOnly: true,
			Secure:   !a.options.IsDevEnv,
		}

		http.SetCookie(*w, &refreshCookie)
	}

	refreshTokenClaims := c.RefreshToken.Token.Claims.(*ClaimsType)
	a.revokeRefreshToken(refreshTokenClaims.StandardClaims.Id)

	setHeader(*w, "X-CSRF-Token", "")
	setHeader(*w, "Auth-Expiry", strconv.FormatInt(time.Now().Add(-1000*time.Hour).Unix(), 10))
	setHeader(*w, "Refresh-Expiry", strconv.FormatInt(time.Now().Add(-1000*time.Hour).Unix(), 10))

	a.myLog("Successfully nullified tokens and csrf string")
	return nil
}

// note: we always grab from the authToken
func (a *Auth) GrabTokenClaims(r *http.Request) (ClaimsType, error) {
	var c credentials
	err := a.buildCredentialsFromRequest(r, &c)
	if err != nil {
		a.myLog("Err grabbing credentials \n" + err.Error())
		return ClaimsType{}, errors.New(err.Error())
	}

	return *c.AuthToken.Token.Claims.(*ClaimsType), nil
}
