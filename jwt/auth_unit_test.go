package jwt

import (
	"errors"
	"net/Url"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var newAuthTests = []struct {
	options Options
	valid   bool
}{
	{
		Options{
			SigningMethodString: "HS256",
			HMACKey:             []byte("test key"),
		},
		true,
	},
	{
		Options{
			SigningMethodString: "HS256",
		},
		false,
	},
	{
		Options{
			SigningMethodString: "RS256",
			PrivateKeyLocation:  "test/priv.rsa",
			PublicKeyLocation:   "test/priv.rsa.pub",
			VerifyOnlyServer:    false,
		},
		true,
	},
	{
		Options{
			SigningMethodString: "RS256",
			PublicKeyLocation:   "test/priv.rsa.pub",
			VerifyOnlyServer:    true,
		},
		true,
	},
	{
		Options{
			SigningMethodString: "RS256",
			PublicKeyLocation:   "test/priv.rsa.pub",
			VerifyOnlyServer:    false,
		},
		false,
	},
	{
		Options{
			SigningMethodString: "RS256",
			PrivateKeyLocation:  "test/priv.rsa",
			VerifyOnlyServer:    false,
		},
		false,
	},
	{
		Options{
			SigningMethodString: "RS256",
			PrivateKeyLocation:  "test/ecdsa_256_priv.pem",
			PublicKeyLocation:   "test/ecdsa_256_pub.pem",
			VerifyOnlyServer:    false,
		},
		false,
	},
	{
		Options{
			SigningMethodString: "ES256",
			PrivateKeyLocation:  "test/ecdsa_256_priv.pem",
			PublicKeyLocation:   "test/ecdsa_256_pub.pem",
			VerifyOnlyServer:    false,
		},
		true,
	},
	{
		Options{
			SigningMethodString: "ES256",
			PublicKeyLocation:   "test/ecdsa_256_pub.pem",
			VerifyOnlyServer:    true,
		},
		true,
	},
	{
		Options{
			SigningMethodString: "ES256",
			PublicKeyLocation:   "test/ecdsa_256_pub.pem",
			VerifyOnlyServer:    false,
		},
		false,
	},
	{
		Options{
			SigningMethodString: "ES256",
			PrivateKeyLocation:  "test/ecdsa_256_priv.pem",
			VerifyOnlyServer:    false,
		},
		false,
	},
	{
		Options{
			SigningMethodString: "ES256",
			PrivateKeyLocation:  "test/priv.rsa",
			PublicKeyLocation:   "test/priv.rsa.pub",
			VerifyOnlyServer:    false,
		},
		false,
	},
}

func TestNew(t *testing.T) {
	var a Auth
	for idx, test := range newAuthTests {
		authErr := New(&a, test.options)
		if test.valid && authErr != nil {
			t.Errorf("Building auth faild when passed valid options; idx: %d; Err: %v; options: %v", idx, authErr, test.options)
		}
		if !test.valid && authErr == nil {
			t.Errorf("Building auth succeeded when passed invalid options; idx: %d; Err: %v; options: %v", idx, authErr, test.options)
		}
	}

	// test the setting of standard token valid times
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}
	if a.options.AuthTokenValidTime != defaultAuthTokenValidTime {
		t.Errorf("Didn't pass authtoken valid time, expected default value of: %v; received %v", defaultAuthTokenValidTime, a.options.AuthTokenValidTime)
	}
	if a.options.RefreshTokenValidTime != defaultRefreshTokenValidTime {
		t.Errorf("Didn't pass authtoken valid time, expected default value of: %v; received %v", defaultRefreshTokenValidTime, a.options.RefreshTokenValidTime)
	}
}

var myErrorHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "I pitty the fool who has a 500 internal server error", 501)
	return
})

func TestSetErrorHandler(t *testing.T) {
	var a Auth
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}

	// test standard
	w := httptest.NewRecorder()
	req, reqErr := http.NewRequest("POST", "http://localhost:8080/", nil)
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}

	a.errorHandler.ServeHTTP(w, req)

	if w.Body.String() != "Internal Server Error\n" {
		t.Errorf("Incorrect response body in default error handler; Expected: %s; Received: %s", "Internal Server Error", w.Body.String())
	}
	if w.Code != 500 {
		t.Errorf("Incorrect response code in default error handler; Expected: %s; Received: %d", 500, w.Code)
	}

	// test custom
	w = httptest.NewRecorder()
	req, reqErr = http.NewRequest("POST", "http://localhost:8080/", nil)
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}

	a.SetErrorHandler(myErrorHandler)

	a.errorHandler.ServeHTTP(w, req)
	if w.Body.String() != "I pitty the fool who has a 500 internal server error\n" {
		t.Errorf("Incorrect response body in custom error handler; Expected: %s; Received: %s", "I pitty the fool who has a 500 internal server error", w.Body.String())
	}
	if w.Code != 501 {
		t.Errorf("Incorrect response code in custom error handler; Expected: %s; Received: %d", 501, w.Code)
	}
}

var MyUnauthorizedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "I pitty the fool who is unauthorized", 402)
	return
})

func TestSetUnauthorizedHandler(t *testing.T) {
	var a Auth
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}

	// test standard
	w := httptest.NewRecorder()
	req, reqErr := http.NewRequest("POST", "http://localhost:8080/", nil)
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}

	a.unauthorizedHandler.ServeHTTP(w, req)

	if w.Body.String() != "Unauthorized\n" {
		t.Errorf("Incorrect response body in default error handler; Expected: %s; Received: %s", "Internal Server Error", w.Body.String())
	}
	if w.Code != 401 {
		t.Errorf("Incorrect response code in default error handler; Expected: %s; Received: %d", 500, w.Code)
	}

	// test custom
	w = httptest.NewRecorder()
	req, reqErr = http.NewRequest("POST", "http://localhost:8080/", nil)
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}

	a.SetUnauthorizedHandler(MyUnauthorizedHandler)

	a.unauthorizedHandler.ServeHTTP(w, req)
	if w.Body.String() != "I pitty the fool who is unauthorized\n" {
		t.Errorf("Incorrect response body in custom error handler; Expected: %s; Received: %s", "I pitty the fool who has a 500 internal server error", w.Body.String())
	}
	if w.Code != 402 {
		t.Errorf("Incorrect response code in custom error handler; Expected: %s; Received: %d", 501, w.Code)
	}
}

func DeleteRefreshToken(jti string) error {
	return errors.New("Testing my function")
}
func TestSetRevokeTokenFunction(t *testing.T) {
	var a Auth
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}

	err := a.revokeRefreshToken("test")
	if err != nil {
		t.Errorf("Tested default revoke refresh token function; Expected: %v; Received: %v", nil, err)
	}

	a.SetRevokeTokenFunction(DeleteRefreshToken)
	err = a.revokeRefreshToken("test")
	if err == nil || err.Error() != "Testing my function" {
		t.Errorf("Tested custom revoke refresh token function; Expected: %v; Received: %v", errors.New("Testing my function"), err)
	}
}

func MyCheckRefreshToken(jti string) bool {
	return false
}
func TestSetCheckTokenIdFunction(t *testing.T) {
	var a Auth
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}

	if !a.checkTokenId("test") {
		t.Error("Checked default token id function; Expected: true; Received: false")
	}

	a.SetCheckTokenIdFunction(MyCheckRefreshToken)
	if a.checkTokenId("test") {
		t.Error("Checked custom token id function; Expected: false; Received: true")
	}
}

func TestIssueNewTokens(t *testing.T) {
	var a Auth
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}
	var claims ClaimsType
	claims.CustomClaims = make(map[string]interface{})
	claims.CustomClaims["foo"] = "bar"

	a.options.VerifyOnlyServer = true
	w := httptest.NewRecorder()
	err := a.IssueNewTokens(w, &claims)
	if err == nil || err.Error() != "Server is not authorized to issue new tokens" {
		t.Errorf("Succeffully issued claims on a verify only server; Expected: %v; Received: %v", errors.New("Server is not authorized to issue new tokens"), err)
	}

	a.options.VerifyOnlyServer = false
	w = httptest.NewRecorder()
	err = a.IssueNewTokens(w, &claims)
	if err != nil {
		t.Errorf("Couldn't issue claims; Expected: %v; Received: %v", nil, err)
	}

	// note @adam-hanna: do more checks? Like checking the claims or token strings?
}

func TestNullifyTokens(t *testing.T) {
	var a Auth
	var c credentials
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}
	revokedTokens = make(map[string]string)
	a.SetRevokeTokenFunction(RevokeRefreshToken) // defined in credentials_unit_test.go
	a.SetCheckTokenIdFunction(CheckRefreshToken) // defined in credentials_unit_test.go
	var claims ClaimsType
	claims.CustomClaims = make(map[string]interface{})
	claims.CustomClaims["foo"] = "bar"

	err := a.buildCredentialsFromClaims(&c, &claims)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}

	authTokenString, authStringErr := c.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", authStringErr)
	}
	refreshTokenString, refreshStringErr := c.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", refreshStringErr)
	}

	// first, test bearer tokens
	a.options.BearerTokens = true

	w := httptest.NewRecorder()
	form := url.Values{}
	form.Add("Auth_Token", authTokenString)
	form.Add("Refresh_Token", refreshTokenString)
	form.Add("X-CSRF-Token", c.CsrfString)

	req, reqErr := http.NewRequest("POST", "http://localhost:8080/", strings.NewReader(form.Encode()))
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	setHeader(w, "Auth_Token", authTokenString)
	setHeader(w, "Refresh_Token", refreshTokenString)
	setHeader(w, "X-CSRF-Token", c.CsrfString)

	nullifyErr := a.NullifyTokens(w, req)
	if nullifyErr != nil {
		t.Errorf("Could not nullify tokens; Err: %v", nullifyErr)
	}

	if w.Header().Get("Auth_Token") != "" ||
		w.Header().Get("Refresh_Token") != "" ||
		w.Header().Get("X-CSRF-Token") != "" {
		t.Errorf("Expected credentials in response header to be blank after nullification; Received auth: %s, refresh: %s, csrf: %s", w.Header().Get("Auth_Token"), w.Header().Get("Refresh_Token"), w.Header().Get("X-CSRF-Token"))
	}

	// Second, check cookies
	a.options.BearerTokens = false
	w = httptest.NewRecorder()
	form = url.Values{}
	form.Add("X-CSRF-Token", c.CsrfString)
	req, reqErr = http.NewRequest("POST", "http://localhost:8080/", strings.NewReader(form.Encode()))
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	authCookie := http.Cookie{
		Name:  "AuthToken",
		Value: authTokenString,
		// Expires:  time.Now().Add(a.options.AuthTokenValidTime),
		HttpOnly: true,
		Secure:   true,
	}
	req.AddCookie(&authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		Expires:  time.Now().Add(a.options.RefreshTokenValidTime),
		HttpOnly: true,
		Secure:   true,
	}
	req.AddCookie(&refreshCookie)

	err = a.setCredentialsOnResponseWriter(w, &c)
	if err != nil {
		t.Errorf("Could not set credentials on response writer; Err: %v", err)
	}

	nullifyErr = a.NullifyTokens(w, req)
	if nullifyErr != nil {
		t.Errorf("Could not nullify tokens; Err: %v", nullifyErr)
	}

	setCookieString := strings.Join(w.Header()["Set-Cookie"], "")
	if w.Header().Get("X-CSRF-Token") != "" || !strings.Contains(setCookieString, "AuthToken=;") || !strings.Contains(setCookieString, "RefreshToken=;") {
		t.Errorf("Credentials were not nullified on response writer; Set-Cookie header: %s; CSRF Header: %s", setCookieString, w.Header().Get("X-CSRF-Token"))
	}

	// finally, check to make sure the refresh token id is being revoked
	refreshTokenClaims := c.RefreshToken.Token.Claims.(*ClaimsType)
	if a.checkTokenId(refreshTokenClaims.StandardClaims.Id) {
		t.Error("Expected refresh token id to have been revoked")
	}
}

func TestGrabTokenClaims(t *testing.T) {
	var a Auth
	var c credentials
	authErr := New(&a, newAuthTests[0].options)
	if authErr != nil {
		t.Errorf("Building auth faild when passed valid options; Err: %v; options: %v", authErr, newAuthTests[0].options)
	}

	var claims ClaimsType
	claims.CustomClaims = make(map[string]interface{})
	claims.CustomClaims["foo"] = "bar"

	err := a.buildCredentialsFromClaims(&c, &claims)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}

	authTokenString, authStringErr := c.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", authStringErr)
	}
	refreshTokenString, refreshStringErr := c.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", refreshStringErr)
	}

	// first, test bearer tokens
	a.options.BearerTokens = true

	form := url.Values{}
	form.Add("Auth_Token", authTokenString)
	form.Add("Refresh_Token", refreshTokenString)
	form.Add("X-CSRF-Token", c.CsrfString)

	req, reqErr := http.NewRequest("POST", "http://localhost:8080/", strings.NewReader(form.Encode()))
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	myNewClaims, grabErr := a.GrabTokenClaims(req)
	if grabErr != nil {
		t.Errorf("Could not grab token cliams from req; Err: %v", grabErr)
	}

	if myNewClaims.CustomClaims["foo"].(string) != "bar" {
		t.Errorf("Claims do not match expectations; Expected: bar; Received: %s", myNewClaims.CustomClaims["foo"].(string))
	}
}
