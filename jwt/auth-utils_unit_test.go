package jwt

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExtractTokenStringsFromReqCookies(t *testing.T) {
	var a Auth
	authErr := New(&a, Options{
		SigningMethodString: "HS256",
		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		Debug:                 true,
		IsDevEnv:              true,
	})
	if authErr != nil {
		t.Errorf("Unable to build jwt auth for testing; Err: %v", authErr)
	}
	authTokenString := "test auth token string"
	refreshTokenString := "test refresh token string"

	// first, test with cookies
	req, err := http.NewRequest("POST", "http://localhost:8080/", nil)
	if err != nil {
		t.Errorf("Error building request for testing; err: %v", err)
	}
	authCookie := http.Cookie{
		Name:  a.options.AuthTokenName,
		Value: authTokenString,
		// Expires:  time.Now().Add(a.options.AuthTokenValidTime),
		HttpOnly: true,
		Secure:   true,
	}
	req.AddCookie(&authCookie)

	refreshCookie := http.Cookie{
		Name:     a.options.RefreshTokenName,
		Value:    refreshTokenString,
		Expires:  time.Now().Add(a.options.RefreshTokenValidTime),
		HttpOnly: true,
		Secure:   true,
	}
	req.AddCookie(&refreshCookie)

	newAuthString, newRefreshString, extractErr := a.extractTokenStringsFromReq(req)
	if extractErr != nil {
		t.Errorf("Error extracting token strings from req; err: %v", extractErr)
	}
	if newAuthString != authTokenString || newRefreshString != refreshTokenString {
		t.Errorf("Extracted token strings do not match expectations; Expected auth: %s, expected refresh: %s; Received auth: %s, received refresh: %s", authTokenString, refreshTokenString, newAuthString, newRefreshString)
	}
}
func TestExtractTokenStringsFromReqTokens(t *testing.T) {
	var a Auth
	authErr := New(&a, Options{
		SigningMethodString: "HS256",
		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		BearerTokens:          true,
		Debug:                 true,
		IsDevEnv:              true,
	})
	if authErr != nil {
		t.Errorf("Unable to build jwt auth for testing; Err: %v", authErr)
	}
	authTokenString := "test auth token string"
	refreshTokenString := "test refresh token string"

	req, err := http.NewRequest("POST", "http://localhost:8080/", nil)
	if err != nil {
		t.Errorf("Error building request for testing; err: %v", err)
	}

	req.Header.Add(a.options.AuthTokenName, authTokenString)
	req.Header.Add(a.options.RefreshTokenName, refreshTokenString)

	newAuthString, newRefreshString, extractErr := a.extractTokenStringsFromReq(req)
	if extractErr != nil {
		t.Errorf("Error extracting token strings from req; err: %v", extractErr)
	}
	if newAuthString != authTokenString || newRefreshString != refreshTokenString {
		t.Errorf("Extracted token strings do not match expectations; Expected auth: %s, expected refresh: %s; Received auth: %s, received refresh: %s", authTokenString, refreshTokenString, newAuthString, newRefreshString)
	}
}

func TestExtractCsrfStringFromReq(t *testing.T) {
	var a Auth
	authErr := New(&a, Options{
		SigningMethodString: "HS256",
		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		Debug:                 true,
		IsDevEnv:              true,
	})
	if authErr != nil {
		t.Errorf("Unable to build jwt auth for testing; Err: %v", authErr)
	}

	s := "test-csrf-string"

	// first, test form encoded
	form := url.Values{}
	form.Add(a.options.CSRFTokenName, s)
	req, err := http.NewRequest("POST", "http://localhost:8080/", strings.NewReader(form.Encode()))
	if err != nil {
		t.Errorf("Error building request for testing; err: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	newCsrf, csrfErr := a.extractCsrfStringFromReq(req)
	if csrfErr != nil {
		t.Errorf("Could not extract csrf from req. err: %v", err)
	}
	if s != newCsrf {
		t.Errorf("Csrf strings do not match; expected: %s; received: %s", s, newCsrf)
	}

	// second, test header encoded
	req, err = http.NewRequest("POST", "http://localhost:8080/", nil)
	if err != nil {
		t.Errorf("Error building request for testing; err: %v", err)
	}
	req.Header.Add(a.options.CSRFTokenName, s)

	newCsrf, csrfErr = a.extractCsrfStringFromReq(req)
	if csrfErr != nil {
		t.Errorf("Could not extract csrf from req. err: %v", err)
	}
	if s != newCsrf {
		t.Errorf("Csrf strings do not match; expected: %s; received: %s", s, newCsrf)
	}

	// third, test header encoded with bearer auth
	req, err = http.NewRequest("POST", "http://localhost:8080/", nil)
	if err != nil {
		t.Errorf("Error building request for testing; err: %v", err)
	}
	req.Header.Add("Authorization", "Bearer "+s)

	newCsrf, csrfErr = a.extractCsrfStringFromReq(req)
	if csrfErr != nil {
		t.Errorf("Could not extract csrf from req. err: %v", err)
	}
	if s != newCsrf {
		t.Errorf("Csrf strings do not match; expected: %s; received: %s", s, newCsrf)
	}

	// finally, test the error case
	req, err = http.NewRequest("POST", "http://localhost:8080/", nil)
	if err != nil {
		t.Errorf("Error building request for testing; err: %v", err)
	}
	newCsrf, csrfErr = a.extractCsrfStringFromReq(req)
	if csrfErr == nil || csrfErr.Error() != "No CSRF string" {
		t.Errorf("Expected error; received err: %v; csrf string: %s", csrfErr, newCsrf)
	}
}

func TestSetCredentialsOnResponseWriterCookie(t *testing.T) {
	var a Auth
	var c credentials
	var claims ClaimsType
	claims.CustomClaims = make(map[string]interface{})
	claims.CustomClaims["foo"] = "bar"
	s := "my csrf string"
	auth := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.6WgdB6Bt68zfgh-icPokRxoOUFp93q-FoQNPZ0V6pec"
	refresh := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.6WgdB6Bt68zfgh-icPokRxoOUFp93q-FoQNPZ0V6pec"

	authErr := New(&a, Options{
		SigningMethodString: "HS256",
		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		Debug:                 false,
		IsDevEnv:              true,
	})
	if authErr != nil {
		t.Errorf("Unable to build jwt auth for testing; Err: %v", authErr)
	}

	err := a.buildCredentialsFromStrings(s, auth, refresh, &c)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	authTokenClaims, ok := c.AuthToken.Token.Claims.(*ClaimsType)
	if !ok {
		t.Error("Cannot read auth token claims")
	}
	refreshTokenClaims, ok := c.RefreshToken.Token.Claims.(*ClaimsType)
	if !ok {
		t.Error("Cannot read refresh token claims")
	}

	w := httptest.NewRecorder()
	err = a.setCredentialsOnResponseWriter(w, &c)
	if err != nil {
		t.Errorf("Could not set credentials on response writer; err: %v", err)
	}

	setCookieString := strings.Join(w.Header()["Set-Cookie"], "")
	if !strings.Contains(setCookieString, a.options.AuthTokenName+"="+auth) || !strings.Contains(setCookieString, a.options.RefreshTokenName+"="+refresh) {
		t.Errorf("Response writer did not contain auth or refresh strings; Set-Cookie header: %s", setCookieString)
	}
	if w.Header().Get(a.options.CSRFTokenName) != c.CsrfString {
		t.Errorf("Response writer does not have correct csrf token; expected: %s; received: %s", c.CsrfString, w.Header().Get(a.options.CSRFTokenName))
	}
	if w.Header().Get("Auth-Expiry") != strconv.FormatInt(authTokenClaims.StandardClaims.ExpiresAt, 10) {
		t.Errorf("Response writer does not have correct auth expiry info; expected %s; received: %s", strconv.FormatInt(authTokenClaims.StandardClaims.ExpiresAt, 10), w.Header().Get("Auth-Expiry"))
	}
	if w.Header().Get("Refresh-Expiry") != strconv.FormatInt(refreshTokenClaims.StandardClaims.ExpiresAt, 10) {
		t.Errorf("Response writer does not have correct auth expiry info; expected %s; received: %s", strconv.FormatInt(refreshTokenClaims.StandardClaims.ExpiresAt, 10), w.Header().Get("Refresh-Expiry"))
	}
}

func TestSetCredentialsOnResponseWriterToken(t *testing.T) {
	var a Auth
	var c credentials
	var claims ClaimsType
	claims.CustomClaims = make(map[string]interface{})
	claims.CustomClaims["foo"] = "bar"
	s := "my csrf string"
	auth := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.6WgdB6Bt68zfgh-icPokRxoOUFp93q-FoQNPZ0V6pec"
	refresh := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.6WgdB6Bt68zfgh-icPokRxoOUFp93q-FoQNPZ0V6pec"

	authErr := New(&a, Options{
		SigningMethodString: "HS256",
		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		BearerTokens:          true,
		Debug:                 false,
		IsDevEnv:              true,
	})
	if authErr != nil {
		t.Errorf("Unable to build jwt auth for testing; Err: %v", authErr)
	}

	err := a.buildCredentialsFromStrings(s, auth, refresh, &c)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}

	// note: don't need to test csrf string, etc. bc tested already
	w := httptest.NewRecorder()
	err = a.setCredentialsOnResponseWriter(w, &c)
	if err != nil {
		t.Errorf("Could not set credentials on response writer; err: %v", err)
	}

	if w.Header().Get(a.options.AuthTokenName) != auth || w.Header().Get(a.options.RefreshTokenName) != refresh {
		t.Errorf("Auth and/or refresh tokens do not match on response writer; expected auth: %s; expected refresh: %s; received auth: %s; received refresh: %s", auth, refresh, w.Header().Get(a.options.AuthTokenName), w.Header().Get(a.options.RefreshTokenName))
	}
}

func TestBuildCredentialsFromRequest(t *testing.T) {
	// this really just combines other functions that we've already tested
	// but we should test it nonetheless
	var a Auth
	var c credentials
	var claims ClaimsType
	claims.CustomClaims = make(map[string]interface{})
	claims.CustomClaims["foo"] = "bar"

	authErr := New(&a, Options{
		SigningMethodString: "HS256",
		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		Debug:                 false,
		IsDevEnv:              true,
	})
	if authErr != nil {
		t.Errorf("Unable to build jwt auth for testing; Err: %v", authErr)
	}

	err := a.buildCredentialsFromClaims(&c, &claims)
	if err != nil {
		t.Errorf("Cound not build credentials for testing; err: %v", err)
	}

	authTokenString, authStringErr := c.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Cound not sign authTokenString; err: %v", authStringErr)
	}
	refreshTokenString, refreshStringErr := c.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Cound not sign refreshTokenString; err: %v", refreshStringErr)
	}

	// now test form encoded tokens
	var a2 Auth
	var c2 credentials
	var claims2 ClaimsType
	claims2.CustomClaims = make(map[string]interface{})
	claims2.CustomClaims["foo"] = "bar"

	authErr = New(&a2, Options{
		SigningMethodString: "HS256",
		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		BearerTokens:          true,
		Debug:                 false,
		IsDevEnv:              true,
	})
	if authErr != nil {
		t.Errorf("Unable to build jwt auth for testing; Err: %v", authErr)
	}

	req2, reqErr := http.NewRequest("POST", "http://localhost:8080/", nil)
	if reqErr != nil {
		t.Errorf("Error building request for testing; err: %v", reqErr)
	}

	req2.Header.Add(a2.options.AuthTokenName, authTokenString)
	req2.Header.Add(a2.options.RefreshTokenName, refreshTokenString)
	req2.Header.Add(a2.options.CSRFTokenName, c.CsrfString)

	err = a2.buildCredentialsFromRequest(req2, &c2)
	if err != nil {
		t.Errorf("Error building credentials from the request; err: %v", err)
	}

	if c2.CsrfString != c.CsrfString {
		t.Errorf("Csrf strings don't match; expected: %s; received: %s", c.CsrfString, c2.CsrfString)
	}

	authTokenString2, authStringErr := c2.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Cound not sign authTokenString; err: %v", authStringErr)
	}
	refreshTokenString2, refreshStringErr := c2.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Cound not sign refreshTokenString; err: %v", refreshStringErr)
	}

	if authTokenString2 != authTokenString || refreshTokenString2 != refreshTokenString {
		t.Errorf("Auth and refresh tokens don't match; expected auth: %s; expected refresh: %s; received auth: %s; received refresh: %s", authTokenString, refreshTokenString, authTokenString2, refreshTokenString2)
	}
}
