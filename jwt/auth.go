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
	AuthTokenName         string
	RefreshTokenName      string
	CSRFTokenName         string
	Debug                 bool
	IsDevEnv              bool
}

const (
	defaultRefreshTokenValidTime  = 72 * time.Hour
	defaultAuthTokenValidTime     = 15 * time.Minute
	defaultBearerAuthTokenName    = "X-Auth-Token"
	defaultBearerRefreshTokenName = "X-Refresh-Token"
	defaultCSRFTokenName          = "X-CSRF-Token"
	defaultCookieAuthTokenName    = "AuthToken"
	defaultCookieRefreshTokenName = "RefreshToken"
)

// ClaimsType : holds the claims encoded in the jwt
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

// TokenRevoker : a type to revoke tokens
type TokenRevoker func(tokenId string) error

func defaultCheckTokenId(tokenId string) bool {
	// return true if the token id is valid (has not been revoked). False for otherwise
	return true
}

// TokenIdChecker : a type to check tokens
type TokenIdChecker func(tokenId string) bool

func defaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", 500)
	return
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unauthorized", 401)
	return
}

// New constructs a new Auth instance with supplied options.
func New(auth *Auth, o Options) error {
	// check if durations have been provided for auth and refresh token exp
	// if not, set them equal to the default
	if o.RefreshTokenValidTime <= 0 {
		o.RefreshTokenValidTime = defaultRefreshTokenValidTime
	}
	if o.AuthTokenValidTime <= 0 {
		o.AuthTokenValidTime = defaultAuthTokenValidTime
	}

	if o.BearerTokens {
		if o.AuthTokenName == "" {
			o.AuthTokenName = defaultBearerAuthTokenName
		}

		if o.RefreshTokenName == "" {
			o.RefreshTokenName = defaultBearerRefreshTokenName
		}
	} else {
		if o.AuthTokenName == "" {
			o.AuthTokenName = defaultCookieAuthTokenName
		}

		if o.RefreshTokenName == "" {
			o.RefreshTokenName = defaultCookieRefreshTokenName
		}
	}

	if o.CSRFTokenName == "" {
		o.CSRFTokenName = defaultCSRFTokenName
	}

	// create the sign and verify keys
	signKey, verifyKey, err := o.buildSignAndVerifyKeys()
	if err != nil {
		return err
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

func (o *Options) buildSignAndVerifyKeys() (signKey interface{}, verifyKey interface{}, err error) {
	if o.SigningMethodString == "HS256" || o.SigningMethodString == "HS384" || o.SigningMethodString == "HS512" {
		return o.buildHMACKeys()

	} else if o.SigningMethodString == "RS256" || o.SigningMethodString == "RS384" || o.SigningMethodString == "RS512" {
		return o.buildRSAKeys()

	} else if o.SigningMethodString == "ES256" || o.SigningMethodString == "ES384" || o.SigningMethodString == "ES512" {
		return o.buildESKeys()

	}

	err = errors.New("Signing method string not recognized!")
	return
}

func (o *Options) buildHMACKeys() (signKey interface{}, verifyKey interface{}, err error) {
	if len(o.HMACKey) == 0 {
		err = errors.New("When using an HMAC-SHA signing method, please provide an HMACKey")
		return
	}
	if !o.VerifyOnlyServer {
		signKey = o.HMACKey
	}
	verifyKey = o.HMACKey

	return
}

func (o *Options) buildRSAKeys() (signKey interface{}, verifyKey interface{}, err error) {
	var signBytes []byte
	var verifyBytes []byte

	// check to make sure the provided options are valid
	if o.PrivateKeyLocation == "" && !o.VerifyOnlyServer {
		err = errors.New("Private key location is required!")
		return
	}
	if o.PublicKeyLocation == "" {
		err = errors.New("Public key location is required!")
		return
	}

	// read the key files
	if !o.VerifyOnlyServer {
		signBytes, err = ioutil.ReadFile(o.PrivateKeyLocation)
		if err != nil {
			return
		}

		signKey, err = jwtGo.ParseRSAPrivateKeyFromPEM(signBytes)
		if err != nil {
			return
		}
	}

	verifyBytes, err = ioutil.ReadFile(o.PublicKeyLocation)
	if err != nil {
		return
	}

	verifyKey, err = jwtGo.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return
	}

	return
}

func (o *Options) buildESKeys() (signKey interface{}, verifyKey interface{}, err error) {
	var signBytes []byte
	var verifyBytes []byte

	// check to make sure the provided options are valid
	if o.PrivateKeyLocation == "" && !o.VerifyOnlyServer {
		err = errors.New("Private key location is required!")
		return
	}
	if o.PublicKeyLocation == "" {
		err = errors.New("Public key location is required!")
		return
	}

	// read the key files
	if !o.VerifyOnlyServer {
		signBytes, err = ioutil.ReadFile(o.PrivateKeyLocation)
		if err != nil {
			return
		}

		signKey, err = jwtGo.ParseECPrivateKeyFromPEM(signBytes)
		if err != nil {
			return
		}
	}

	verifyBytes, err = ioutil.ReadFile(o.PublicKeyLocation)
	if err != nil {
		return
	}

	verifyKey, err = jwtGo.ParseECPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return
	}

	return
}

// SetErrorHandler : add methods to allow the changing of default functions
func (a *Auth) SetErrorHandler(handler http.Handler) {
	a.errorHandler = handler
}

// SetUnauthorizedHandler : set the 401 handler
func (a *Auth) SetUnauthorizedHandler(handler http.Handler) {
	a.unauthorizedHandler = handler
}

// SetRevokeTokenFunction : set the function which revokes a token
func (a *Auth) SetRevokeTokenFunction(revoker TokenRevoker) {
	a.revokeRefreshToken = revoker
}

// SetCheckTokenIdFunction : set the function which checks token id's
func (a *Auth) SetCheckTokenIdFunction(checker TokenIdChecker) {
	a.checkTokenId = checker
}

// Handler implements the http.HandlerFunc for integration with the standard net/http lib.
func (a *Auth) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Process the request. If it returns an error,
		// that indicates the request should not continue.
		jwtErr := a.Process(w, r)
		var j jwtError

		// If there was an error, do not continue.
		if jwtErr != nil {
			a.myLog("Error processing jwts\n" + jwtErr.Error())
			_ = a.NullifyTokens(w, r)
			if reflect.TypeOf(jwtErr) == reflect.TypeOf(&j) && jwtErr.Type/100 == 4 {
				a.unauthorizedHandler.ServeHTTP(w, r)
				return
			}

			a.errorHandler.ServeHTTP(w, r)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// HandlerFunc works identically to Handler, but takes a HandlerFunc instead of a Handler.
func (a *Auth) HandlerFunc(fn http.HandlerFunc) http.Handler {
	if fn == nil {
		return a.Handler(nil)
	}
	return a.Handler(fn)
}

// HandlerFuncWithNext is a special implementation for Negroni, but could be used elsewhere.
func (a *Auth) HandlerFuncWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	jwtErr := a.Process(w, r)
	var j jwtError

	// If there was an error, do not call next.
	if jwtErr == nil && next != nil {
		next(w, r)
	} else {
		a.myLog("Error processing jwts\n" + jwtErr.Error())
		_ = a.NullifyTokens(w, r)
		if reflect.TypeOf(jwtErr) == reflect.TypeOf(&j) && jwtErr.Type/100 == 4 {
			a.unauthorizedHandler.ServeHTTP(w, r)
		} else {
			a.errorHandler.ServeHTTP(w, r)
		}
	}
}

// Process runs the actual checks and returns an error if the middleware chain should stop.
func (a *Auth) Process(w http.ResponseWriter, r *http.Request) *jwtError {
	// cookies aren't included with options, so simply pass through
	if r.Method == "OPTIONS" {
		a.myLog("Method is OPTIONS")
		return nil
	}

	// grab the credentials from the request
	var c credentials
	if err := a.buildCredentialsFromRequest(r, &c); err != nil {
		return newJwtError(err, 500)
	}

	// check the credential's validity; updating expiry's if necessary and/or allowed
	if err := c.validateAndUpdateCredentials(); err != nil {
		return newJwtError(err, 500)
	}

	a.myLog("Successfully checked / refreshed jwts")

	// if we've made it this far, everything is valid!
	// And tokens have been refreshed if need-be
	if !a.options.VerifyOnlyServer {
		if err := a.setCredentialsOnResponseWriter(w, &c); err != nil {
			return newJwtError(err, 500)
		}
	}

	return nil
}

// IssueNewTokens : and also modify create refresh and auth token functions!
func (a *Auth) IssueNewTokens(w http.ResponseWriter, claims *ClaimsType) error {
	if a.options.VerifyOnlyServer {
		a.myLog("Server is not authorized to issue new tokens")
		return errors.New("Server is not authorized to issue new tokens")

	}

	var c credentials
	err := a.buildCredentialsFromClaims(&c, claims)
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.setCredentialsOnResponseWriter(w, &c)
	if err != nil {
		return errors.New(err.Error())
	}

	return nil
}

// NullifyTokens : invalidate tokens
// note @adam-hanna: what if there are no credentials in the request?
func (a *Auth) NullifyTokens(w http.ResponseWriter, r *http.Request) error {
	var c credentials
	err := a.buildCredentialsFromRequest(r, &c)
	if err != nil {
		a.myLog("Err building credentials\n" + err.Error())
		return errors.New(err.Error())
	}

	if a.options.BearerTokens {
		// tokens are not in cookies
		setHeader(w, a.options.AuthTokenName, "")
		setHeader(w, a.options.RefreshTokenName, "")
	} else {
		authCookie := http.Cookie{
			Name:     a.options.AuthTokenName,
			Value:    "",
			Expires:  time.Now().Add(-1000 * time.Hour),
			HttpOnly: true,
			Secure:   !a.options.IsDevEnv,
		}

		http.SetCookie(w, &authCookie)

		refreshCookie := http.Cookie{
			Name:     a.options.RefreshTokenName,
			Value:    "",
			Expires:  time.Now().Add(-1000 * time.Hour),
			HttpOnly: true,
			Secure:   !a.options.IsDevEnv,
		}

		http.SetCookie(w, &refreshCookie)
	}
	if c.RefreshToken != nil && c.RefreshToken.Token != nil && c.RefreshToken.Token.Claims != nil {
		refreshTokenClaims := c.RefreshToken.Token.Claims.(*ClaimsType)
		a.revokeRefreshToken(refreshTokenClaims.StandardClaims.Id)
	}

	setHeader(w, a.options.CSRFTokenName, "")
	setHeader(w, "Auth-Expiry", strconv.FormatInt(time.Now().Add(-1000*time.Hour).Unix(), 10))
	setHeader(w, "Refresh-Expiry", strconv.FormatInt(time.Now().Add(-1000*time.Hour).Unix(), 10))

	a.myLog("Successfully nullified tokens and csrf string")
	return nil
}

// GrabTokenClaims : extract the claims from the request
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
