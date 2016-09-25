package jwt

import (
	"testing"
	"time"
)

var revokedTokens map[string]string

func CheckRefreshToken(jti string) bool {
	return revokedTokens[jti] == ""
}
func RevokeRefreshToken(jti string) error {
	revokedTokens[jti] = "revoked"
	return nil
}

func TestInitRevokedTokenMap(t *testing.T) {
	revokedTokens = make(map[string]string)
}

func TestBuildCredentialsFromClaims(t *testing.T) {
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
		t.Errorf("Unable to build credentials; Err: %v", err)
	}

	if c.CsrfString == "" {
		t.Errorf("No csrf string in credentials; Csrf: %s", c.CsrfString)
	}

	// note @adam-hanna: how to check c.options.CheckTokenId == a.checkTokenId?
	if c.options.AuthTokenValidTime != a.options.AuthTokenValidTime ||
		c.options.RefreshTokenValidTime != a.options.RefreshTokenValidTime ||
		c.options.VerifyOnlyServer != a.options.VerifyOnlyServer ||
		c.options.SigningMethodString != a.options.SigningMethodString ||
		c.options.Debug != a.options.Debug {
		t.Error("Credentials were not built with necessary info from Auth")
	}

	// note: we do fairly extensive testing of the tokens in the tokens file
	//       so I don't see a need to repeat those tests, here
}

func TestBuildCredentialsFromStrings(t *testing.T) {
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

	// note @adam-hanna: how to check c.options.CheckTokenId == a.checkTokenId?
	if c.options.AuthTokenValidTime != a.options.AuthTokenValidTime ||
		c.options.RefreshTokenValidTime != a.options.RefreshTokenValidTime ||
		c.options.VerifyOnlyServer != a.options.VerifyOnlyServer ||
		c.options.SigningMethodString != a.options.SigningMethodString ||
		c.options.Debug != a.options.Debug {
		t.Error("Credentials were not built with necessary info from Auth")
	}

	// note: we do fairly extensive testing of the tokens in the tokens file
	//       so I don't see a need to repeat those tests, here
}

func TestValidateCsrfStringAgainstCredentials(t *testing.T) {
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
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	authClaims := c.AuthToken.Token.Claims.(*ClaimsType)
	refreshClaims := c.RefreshToken.Token.Claims.(*ClaimsType)

	if c.CsrfString == "" || authClaims.Csrf == "" || refreshClaims.Csrf == "" {
		t.Errorf("No csrf string in credentials; Csrf: %s; Auth Csrf: %s; Refresh Csrf: %s", c.CsrfString, authClaims.Csrf, refreshClaims.Csrf)
	}
	if c.CsrfString != authClaims.Csrf || authClaims.Csrf != refreshClaims.Csrf {
		t.Errorf("Csrf strings don't match; Csrf: %s; Auth Csrf: %s; Refresh Csrf: %s", c.CsrfString, authClaims.Csrf, refreshClaims.Csrf)
	}
}

func TestGenerateNewCsrfString(t *testing.T) {
	s, err := generateNewCsrfString()
	if err != nil {
		t.Errorf("Could not generate a new csrf string; Err: %v", err)
	}
	// note @adam-hanna: I hate hard coding this...
	if len([]rune(s)) == 32 {
		t.Errorf("Csrf is not sufficiently long enough; Expected: 32; Received: %d", len([]rune(s)))
	}
}

func TestUpdateAuthTokenFromRefreshToken(t *testing.T) {
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

	a.SetRevokeTokenFunction(RevokeRefreshToken)
	a.SetCheckTokenIdFunction(CheckRefreshToken)

	// note: need to use this build function bc it sets expiry times from Now()
	err := a.buildCredentialsFromClaims(&c, &claims)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	// note: now need to build from strings, bc token.Valid is only true if parsed
	authTokenString, authStringErr := c.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", authStringErr)
	}
	refreshTokenString, refreshStringErr := c.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", refreshStringErr)
	}
	err = a.buildCredentialsFromStrings(c.CsrfString, authTokenString, refreshTokenString, &c)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}

	refreshClaims := c.RefreshToken.Token.Claims.(*ClaimsType)

	revokeErr := RevokeRefreshToken(refreshClaims.StandardClaims.Id)
	if revokeErr != nil {
		t.Errorf("Unable to revoke refresh token; Err: %v", err)
	}

	err = c.updateAuthTokenFromRefreshToken()
	if err == nil || err.Error() != "Refresh token has been revoked. Cannot update auth token" {
		t.Errorf("Revoked tokens should not be used to update auth tokens; Err: %v", err)
	}

	delete(revokedTokens, refreshClaims.StandardClaims.Id)
	err = c.updateAuthTokenFromRefreshToken()
	if err != nil {
		t.Errorf("Refresh token has been removed from the revoked list and should be allowed to update auth token; Err: %v", err)
	}

	c.RefreshToken.Token.Valid = false
	err = c.updateAuthTokenFromRefreshToken()
	if err == nil || err.Error() != "Refresh token is invalid. Cannot refresh auth token." {
		t.Errorf("Refresh token is invalid and should not be allowed to update auth token; Err: %v", err)
	}
}

func TestValidateAndUpdateCredentials(t *testing.T) {
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
	// note: need to use this build function bc it sets expiry times from Now()
	err := a.buildCredentialsFromClaims(&c, &claims)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	// note: now need to build from strings, bc token.Valid is only true if parsed
	authTokenString, authStringErr := c.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", authStringErr)
	}
	refreshTokenString, refreshStringErr := c.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", refreshStringErr)
	}
	err = a.buildCredentialsFromStrings(c.CsrfString, authTokenString, refreshTokenString, &c)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}

	tempCsrf := c.CsrfString
	c.CsrfString = "fake string"

	err = c.validateAndUpdateCredentials()
	if err == nil || err.Error() != "CSRF token doesn't match value in jwts" {
		t.Errorf("Expected error bc Csrf string doesn't match jwt's. Insted, received Err: ", err)
	}

	c.CsrfString = tempCsrf

	// now, expect everything to pass and a new csrf string to be generated and refresh token
	// expiry updated
	oldAuthClaimsCsrf := c.AuthToken.Token.Claims.(*ClaimsType).Csrf
	oldAuthExpiry := c.AuthToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt
	oldRefreshClaimsCsrf := c.RefreshToken.Token.Claims.(*ClaimsType).Csrf
	oldRefreshExpiry := c.RefreshToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt

	// need to sleep to check expiry time differences
	duration := time.Duration(1) * time.Second // Pause for 1 seconds
	time.Sleep(duration)

	err = c.validateAndUpdateCredentials()
	if err != nil {
		t.Errorf("Could not update and refresh credentials; Err: ", err)
	}
	newAuthClaimsCsrf := c.AuthToken.Token.Claims.(*ClaimsType).Csrf
	newAuthExpiry := c.AuthToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt
	newRefreshClaimsCsrf := c.RefreshToken.Token.Claims.(*ClaimsType).Csrf
	newRefreshExpiry := c.RefreshToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt

	if tempCsrf == c.CsrfString ||
		oldAuthClaimsCsrf == newAuthClaimsCsrf ||
		oldRefreshClaimsCsrf == newRefreshClaimsCsrf {
		t.Error("Csrf strings were not updated")
	}
	if c.CsrfString != newAuthClaimsCsrf || c.CsrfString != newRefreshClaimsCsrf {
		t.Error("New csrf strings do not match in credentials")
	}

	if oldAuthExpiry != newAuthExpiry {
		t.Errorf("Expected auth expiry to not be updated: old: %v; new: %v", oldAuthExpiry, newAuthExpiry)
	}
	if oldRefreshExpiry == newRefreshExpiry || (newRefreshExpiry-oldRefreshExpiry) <= 0 {
		t.Errorf("Expected refresh expiry to be updated: old: %v; new: %v", oldRefreshExpiry, newRefreshExpiry)
	}

	// if this is a verify only server, we don't want any changes to be made to our creds
	// note: need to use this build function bc it sets expiry times from Now()
	err = a.buildCredentialsFromClaims(&c, &claims)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	// note: now need to build from strings, bc token.Valid is only true if parsed
	authTokenString, authStringErr = c.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", authStringErr)
	}
	refreshTokenString, refreshStringErr = c.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", refreshStringErr)
	}
	err = a.buildCredentialsFromStrings(c.CsrfString, authTokenString, refreshTokenString, &c)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	c.options.VerifyOnlyServer = true
	tempCsrf = c.CsrfString
	oldAuthClaimsCsrf = c.AuthToken.Token.Claims.(*ClaimsType).Csrf
	oldAuthExpiry = c.AuthToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt
	oldRefreshClaimsCsrf = c.RefreshToken.Token.Claims.(*ClaimsType).Csrf
	oldRefreshExpiry = c.RefreshToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt

	// need to sleep to check expiry time differences
	duration = time.Duration(1) * time.Second // Pause for 1 seconds
	time.Sleep(duration)

	err = c.validateAndUpdateCredentials()
	if err != nil {
		t.Errorf("Could not update and refresh credentials; Err: ", err)
	}

	newAuthClaimsCsrf = c.AuthToken.Token.Claims.(*ClaimsType).Csrf
	newAuthExpiry = c.AuthToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt
	newRefreshClaimsCsrf = c.RefreshToken.Token.Claims.(*ClaimsType).Csrf
	newRefreshExpiry = c.RefreshToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt

	if tempCsrf != c.CsrfString ||
		oldAuthClaimsCsrf != newAuthClaimsCsrf ||
		oldRefreshClaimsCsrf != newRefreshClaimsCsrf {
		t.Error("Csrf strings were updated but this server is not authorized to do so")
	}
	if c.CsrfString != newAuthClaimsCsrf || c.CsrfString != newRefreshClaimsCsrf {
		t.Error("New csrf strings do not match in credentials")
	}

	if oldAuthExpiry != newAuthExpiry {
		t.Errorf("Expected auth expiry to not be updated: old: %v; new: %v", oldAuthExpiry, newAuthExpiry)
	}
	if oldRefreshExpiry != newRefreshExpiry {
		t.Errorf("Expected refresh expiry to not be updated: old: %v; new: %v", oldRefreshExpiry, newRefreshExpiry)
	}

	// test invalid auth tokens
	a.options.AuthTokenValidTime = 1 * time.Nanosecond
	err = a.buildCredentialsFromClaims(&c, &claims)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	// need to sleep so auth token won't be valid
	duration = time.Duration(1) * time.Second // Pause for 1 second
	time.Sleep(duration)
	// note: now need to build from strings, bc token.Valid is only true if parsed
	authTokenString, authStringErr = c.AuthToken.Token.SignedString(a.signKey)
	if authStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", authStringErr)
	}
	refreshTokenString, refreshStringErr = c.RefreshToken.Token.SignedString(a.signKey)
	if refreshStringErr != nil {
		t.Errorf("Unable to build credentials; Err: %v", refreshStringErr)
	}
	err = a.buildCredentialsFromStrings(c.CsrfString, authTokenString, refreshTokenString, &c)
	if err != nil {
		t.Errorf("Unable to build credentials; Err: %v", err)
	}
	c.options.VerifyOnlyServer = true
	err = c.validateAndUpdateCredentials()
	if err == nil || err.Error() != "Auth token is expired and server is not authorized to issue new tokens" {
		t.Errorf("Auth token is not valid, and server is not allowed to update tokens but did or expierenced some other err; Err: %v", err)
	}

	c.options.VerifyOnlyServer = false
	tempCsrf = c.CsrfString
	oldAuthClaimsCsrf = c.AuthToken.Token.Claims.(*ClaimsType).Csrf
	oldAuthExpiry = c.AuthToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt
	oldRefreshClaimsCsrf = c.RefreshToken.Token.Claims.(*ClaimsType).Csrf
	oldRefreshExpiry = c.RefreshToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt

	// need to sleep to check expiry time differences
	duration = time.Duration(1) * time.Second // Pause for 1 seconds
	time.Sleep(duration)
	err = c.validateAndUpdateCredentials()
	if err != nil {
		t.Errorf("Could not update and refresh credentials; Err: ", err)
	}

	newAuthClaimsCsrf = c.AuthToken.Token.Claims.(*ClaimsType).Csrf
	newAuthExpiry = c.AuthToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt
	newRefreshClaimsCsrf = c.RefreshToken.Token.Claims.(*ClaimsType).Csrf
	newRefreshExpiry = c.RefreshToken.Token.Claims.(*ClaimsType).StandardClaims.ExpiresAt

	if tempCsrf == c.CsrfString ||
		oldAuthClaimsCsrf == newAuthClaimsCsrf ||
		oldRefreshClaimsCsrf == newRefreshClaimsCsrf {
		t.Error("Csrf strings were not updated")
	}
	if c.CsrfString != newAuthClaimsCsrf || c.CsrfString != newRefreshClaimsCsrf {
		t.Error("New csrf strings do not match in credentials")
	}

	if oldAuthExpiry == newAuthExpiry || (newAuthExpiry-oldAuthExpiry) <= 0 {
		t.Errorf("Expected auth expiry to be updated: old: %v; new: %v", oldAuthExpiry, newAuthExpiry)
	}
	if oldRefreshExpiry == newRefreshExpiry || (newRefreshExpiry-oldRefreshExpiry) <= 0 {
		t.Errorf("Expected refresh expiry to be updated: old: %v; new: %v", oldRefreshExpiry, newRefreshExpiry)
	}
}
