package jwt

import (
	"io/ioutil"
	"testing"
	"time"

	jwtGo "github.com/dgrijalva/jwt-go"
)

var rsaTestTokenStrings = []struct {
	name         string
	tokenString  string
	alg          string
	customClaims map[string]interface{}
	validTime    time.Duration
	valid        bool
}{
	{
		"Basic RS256",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.YYJhLzfEQmjb1ta8E4QQIpA9Zop3bSxo27AunXU074X65Xj8nNGE-YqpHI3T1pd_zeFTyhORLz824Ch0xjHTci8Av5E16gSdRkroxX1Ts-Bg_bVb-zlvNcWPRFKjIVg78o3mW3o-HyxTE2B2jG8nCsc4U-oeQcPAeNJaMMd6QjhXHv9XmBbhlTYWZTnV9f3OHAfAS3bHtF832gSKCzzfGJm6uLWDwmTspoi1jg-0yZKUCRxFuQKL3nuKZDog4LHl3PRw1FsX4cN8m5d9I48MzYah3Z8YOIGS7mNhsS0P2b9hfyE-hxZlWJEfB92HMXOxguRcpNUHQUo7V3z6EBfRoA",
		"RS256",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic RS384",
		"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.GoNdGYp3PtyCoPESbyWbhLJx_vcmJ8Me3mfUEvYVn6izSLwsTkha0OuuHf5rZ5R6X92z6ORyP4yRm7LPrETaTpgXUHnzXkpeSfZG9ri8ERCCK30y_Y7nR7qOm1bMUxDFkmfo4NYMSsIP2SVGSde-1lKsEp4hzw-EGL2CeDa51H-QtshUetM3fZ1hl3kertQzXQf3zQmYEjSJWosrWHLW0KacyxZOnsQ_fJ0ogu2Buhc5IFi855dnPxFYfTeDQN_7Dnp9M8SXU-C4ginkYyzPap7dNsxYhdGY-FqTj24cDY-LL3VVD387do8yv_n6EBiK3Q5LV2Y5VAnSDAPXgnqtGg",
		"RS384",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic RS512",
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.sL2ju6ycqLHxp1GZ64KuuSYEvu6eEbUjUGqBfR2epvcKTQwUy7vdV1cGsGnY2Hma7W_1Lcm9311K126_0c0kd3DYquJQnpiiJM-fc1z9dJpq7l3fKF6OGDWUO8zNT9Eb4HlBq1kLCQI_2k-ZbEXkGr5_Kc-UPQYcwin4M2jRwTu2Gsq0MTb-XvlNQvO5noArRu15KVzSamwahrrodd6lSj5qd1U65_Xw0ON6UJJRStwAk1yM_O5UmacjdtSGpgW8m2jUMiS8IkVhDe2v8k-VYSZwoGYZCmt--wEbM6apR4nNt5IVgE3cDjCLmWEVH6nqnGND9VsM5jgekcqF16pn8w",
		"RS512",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic RS512, but alg is indicated as RS256",
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.sL2ju6ycqLHxp1GZ64KuuSYEvu6eEbUjUGqBfR2epvcKTQwUy7vdV1cGsGnY2Hma7W_1Lcm9311K126_0c0kd3DYquJQnpiiJM-fc1z9dJpq7l3fKF6OGDWUO8zNT9Eb4HlBq1kLCQI_2k-ZbEXkGr5_Kc-UPQYcwin4M2jRwTu2Gsq0MTb-XvlNQvO5noArRu15KVzSamwahrrodd6lSj5qd1U65_Xw0ON6UJJRStwAk1yM_O5UmacjdtSGpgW8m2jUMiS8IkVhDe2v8k-VYSZwoGYZCmt--wEbM6apR4nNt5IVgE3cDjCLmWEVH6nqnGND9VsM5jgekcqF16pn8w",
		"RS256",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		false,
	},
}

var ecdsaTestTokenStrings = []struct {
	name         string
	tokenString  string
	alg          string
	customClaims map[string]interface{}
	validTime    time.Duration
	valid        bool
}{
	{
		"Basic ES256",
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.hp9dzn_FT85DJHD0-cAMmK7UhBMcxZWlKObcwzGLjssAbJLM2TwIL5OWkNTF31h-Nih-0019KhOSaV-6d34Mxg",
		"ES256",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic ES384",
		"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.VF3GJc0vdqZz8nnWJP7kabTpspOC8djfIZ8SGZhQ7nPfgsShEcfouxaj46d-AbL8zrlM9pcP0YYlaIbHImWJzEqknm7PeJgkI6Uue3p_mLrSUOqMx8rSrK071Yv2-P7H",
		"ES384",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic ES512",
		"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.ADzY_COC0Yp77JbHF2Wp_wbaZkNENtx7ZR1HJ25ey4J-EGVIxKNJv0Q9cK_dUtLFQeWxZYoupgItEWbNJOr7T513AUyV39RUTFI27skbC9dcj3zi1sxm2yXu79Y_nutpa6_5xtFmd7pCKU6DI1AdKXGetZsnWrpkN83huGaEKqcH92M5",
		"ES512",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic ES512, but alg is given as 256",
		"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.ADzY_COC0Yp77JbHF2Wp_wbaZkNENtx7ZR1HJ25ey4J-EGVIxKNJv0Q9cK_dUtLFQeWxZYoupgItEWbNJOr7T513AUyV39RUTFI27skbC9dcj3zi1sxm2yXu79Y_nutpa6_5xtFmd7pCKU6DI1AdKXGetZsnWrpkN83huGaEKqcH92M5",
		"ES256",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		false,
	},
}

var hsTestTokenStrings = []struct {
	name         string
	tokenString  string
	alg          string
	customClaims map[string]interface{}
	validTime    time.Duration
	valid        bool
}{
	{
		"Basic HS256",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.6WgdB6Bt68zfgh-icPokRxoOUFp93q-FoQNPZ0V6pec",
		"HS256",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic HS384",
		"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.J-wDrXp2jQ7Hhh50xl4wIjgB28qvVqcx6NABbMsvXgyPJF-kagwgsC1bo9RNrxUh",
		"HS384",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic HS512",
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.z5BB-IZLc9QUewcVFAw5BCQ7qIng_O6hdYxzmDbjv5wVCBhhczohW5TsFiNgr83m_8FKYcmXb_hHw5_KNaNQgg",
		"HS512",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		true,
	},
	{
		"Basic HS512, but alg is listed as 256",
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJDc3JmIjoiIiwiQ3VzdG9tQ2xhaW1zIjp7ImZvbyI6ImJhciJ9fQ.z5BB-IZLc9QUewcVFAw5BCQ7qIng_O6hdYxzmDbjv5wVCBhhczohW5TsFiNgr83m_8FKYcmXb_hHw5_KNaNQgg",
		"HS256",
		map[string]interface{}{"foo": "bar"},
		15 * time.Minute,
		false,
	},
}

func TestBuildingRSAFromTokenStrings(t *testing.T) {
	verifyBytes, err := ioutil.ReadFile("test/priv.rsa.pub")
	if err != nil {
		t.Errorf("Unable to read RSA public key file: %v", err)
	}

	verifyKey, err := jwtGo.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		t.Errorf("Unable to parse RSA public key: %v", err)
	}

	for i, data := range rsaTestTokenStrings {
		cOptions := credentialsOptions{
			SigningMethodString: data.alg,
		}
		c := credentials{
			options: cOptions,
		}

		tempToken := c.buildTokenWithClaimsFromString(data.tokenString, verifyKey, defaultAuthTokenValidTime)
		if tempToken.ParseErr != nil && data.valid {
			t.Errorf("Unable to parse RSA token string at idx: %d; Err: %v", i, tempToken.ParseErr)
		} else if tempToken.ParseErr == nil && !data.valid {
			t.Errorf("Token parsed correctly, but is invalid at RSA token string idx: %d", i)
		}

		tempTokenClaims, ok := tempToken.Token.Claims.(*ClaimsType)
		if !ok {
			t.Errorf("Unable to read claims from RSA token string at idx: %d; Claims: %v", i, tempToken.Token.Claims)
		}

		if tempTokenClaims.CustomClaims["foo"].(string) != data.customClaims["foo"].(string) && data.valid {
			t.Errorf("Invalid custom claims from RSA token string at idx: %d; Claims: %v; Expected: %v", i, tempTokenClaims.CustomClaims, data.customClaims)
		}

		if tempToken.Token.Header["alg"].(string) != data.alg && data.valid {
			t.Errorf("Incorrect signing method on RSA token string at idx: %d; Alg: %s; Expected: %s", i, tempToken.Token.Header["alg"].(string), data.alg)
		}
	}
}

func TestBuildECDSAFromTokenStrings(t *testing.T) {
	var err error
	for i, data := range ecdsaTestTokenStrings {
		var verifyBytes []byte
		var verifyKey interface{}

		switch data.alg {
		case "ES256":
			verifyBytes, err = ioutil.ReadFile("test/ecdsa_256_pub.pem")
			if err != nil {
				t.Errorf("Unable to read ECDSA public key file: %v", err)
			}

			verifyKey, err = jwtGo.ParseECPublicKeyFromPEM(verifyBytes)
			if err != nil {
				t.Errorf("Unable to parse ECDSA public key: %v", err)
			}
		case "ES384":
			verifyBytes, err = ioutil.ReadFile("test/ecdsa_384_pub.pem")
			if err != nil {
				t.Errorf("Unable to read ECDSA public key file: %v", err)
			}

			verifyKey, err = jwtGo.ParseECPublicKeyFromPEM(verifyBytes)
			if err != nil {
				t.Errorf("Unable to parse ECDSA public key: %v", err)
			}
		case "ES512":
			verifyBytes, err = ioutil.ReadFile("test/ecdsa_512_pub.pem")
			if err != nil {
				t.Errorf("Unable to read ECDSA public key file: %v", err)
			}

			verifyKey, err = jwtGo.ParseECPublicKeyFromPEM(verifyBytes)
			if err != nil {
				t.Errorf("Unable to parse ECDSA public key: %v", err)
			}

		default:
			t.Errorf("Unrecognized ECDSA alg: %s", data.alg)
		}

		cOptions := credentialsOptions{
			SigningMethodString: data.alg,
		}
		c := credentials{
			options: cOptions,
		}

		tempToken := c.buildTokenWithClaimsFromString(data.tokenString, verifyKey, defaultAuthTokenValidTime)
		if tempToken.ParseErr != nil && data.valid {
			t.Errorf("Unable to parse ECDSA token string at idx: %d; Err: %v", i, tempToken.ParseErr)
		} else if tempToken.ParseErr == nil && !data.valid {
			t.Errorf("Token parsed correctly, but is invalid at ECDSA token string idx: %d", i)
		}

		tempTokenClaims, ok := tempToken.Token.Claims.(*ClaimsType)
		if !ok {
			t.Errorf("Unable to read claims from ECDSA token string at idx: %d; Claims: %v", i, tempToken.Token.Claims)
		}

		if tempTokenClaims.CustomClaims["foo"].(string) != data.customClaims["foo"].(string) && data.valid {
			t.Errorf("Invalid custom claims from ECDSA token string at idx: %d; Claims: %v; Expected: %v", i, tempTokenClaims.CustomClaims, data.customClaims)
		}

		if tempToken.Token.Header["alg"].(string) != data.alg && data.valid {
			t.Errorf("Incorrect signing method on ECDSA token string at idx: %d; Alg: %s; Expected: %s", i, tempToken.Token.Header["alg"].(string), data.alg)
		}
	}

}

func TestBuildHSFromTokenStrings(t *testing.T) {
	var key = []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`)

	for i, data := range hsTestTokenStrings {
		cOptions := credentialsOptions{
			SigningMethodString: data.alg,
		}
		c := credentials{
			options: cOptions,
		}

		tempToken := c.buildTokenWithClaimsFromString(data.tokenString, key, defaultAuthTokenValidTime)
		if tempToken.ParseErr != nil && data.valid {
			t.Errorf("Unable to parse HS token string at idx: %d; Err: %v", i, tempToken.ParseErr)
		} else if tempToken.ParseErr == nil && !data.valid {
			t.Errorf("Token parsed correctly, but is invalid at HS token string idx: %d", i)
		}

		tempTokenClaims, ok := tempToken.Token.Claims.(*ClaimsType)
		if !ok {
			t.Errorf("Unable to read claims from HS token string at idx: %d; Claims: %v", i, tempToken.Token.Claims)
		}

		if tempTokenClaims.CustomClaims["foo"].(string) != data.customClaims["foo"].(string) && data.valid {
			t.Errorf("Invalid custom claims from HS token string at idx: %d; Claims: %v; Expected: %v", i, tempTokenClaims.CustomClaims, data.customClaims)
		}

		if tempToken.Token.Header["alg"].(string) != data.alg && data.valid {
			t.Errorf("Incorrect signing method on HS token string at idx: %d; Alg: %s; Expected: %s", i, tempToken.Token.Header["alg"].(string), data.alg)
		}
	}
}

func TestBuildingRSAFromClaims(t *testing.T) {
	signBytes, err := ioutil.ReadFile("test/priv.rsa")
	if err != nil {
		t.Errorf("Unable to read RSA private key file: %v", err)
	}

	signKey, err := jwtGo.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		t.Errorf("Unable to parse RSA private key: %v", err)
	}

	for i, data := range rsaTestTokenStrings {
		cOptions := credentialsOptions{
			SigningMethodString: data.alg,
		}
		c := credentials{
			options: cOptions,
		}
		var claims ClaimsType
		claims.CustomClaims = data.customClaims

		tempToken := c.newTokenWithClaims(&claims, data.validTime)

		tempTokenString, err := tempToken.Token.SignedString(signKey)
		if err != nil {
			t.Errorf("Unable to sign token with private key: %v", err)
		}

		if tempTokenString != data.tokenString && data.valid {
			t.Errorf("RSA token strings do not match at idx: %d; String: %s, Expected: %s", i, tempTokenString, data.tokenString)
		} else if tempTokenString == data.tokenString && !data.valid {
			t.Errorf("RSA token strings match but were not expected to at idx: %d; String: %s, Expected: %s", i, tempTokenString, data.tokenString)
		}
	}
}

// note @adam-hanna: ECDSA will produce different strings each time
// func TestBuildingECDSAFromClaims(t *testing.T) {
// 	var err error
// 	for i, data := range ecdsaTestTokenStrings {
// 		var signBytes []byte
// 		var signKey interface{}

// 		switch data.alg {
// 		case "ES256":
// 			signBytes, err = ioutil.ReadFile("test/ecdsa_256_priv.pem")
// 			if err != nil {
// 				t.Errorf("Unable to read ECDSA private key file: %v", err)
// 			}

// 			signKey, err = jwtGo.ParseECPrivateKeyFromPEM(signBytes)
// 			if err != nil {
// 				t.Errorf("Unable to parse ECDSA private key: %v", err)
// 			}
// 		case "ES384":
// 			signBytes, err = ioutil.ReadFile("test/ecdsa_384_priv.pem")
// 			if err != nil {
// 				t.Errorf("Unable to read ECDSA private key file: %v", err)
// 			}

// 			signKey, err = jwtGo.ParseECPrivateKeyFromPEM(signBytes)
// 			if err != nil {
// 				t.Errorf("Unable to parse ECDSA private key: %v", err)
// 			}
// 		case "ES512":
// 			signBytes, err = ioutil.ReadFile("test/ecdsa_512_priv.pem")
// 			if err != nil {
// 				t.Errorf("Unable to read ECDSA private key file: %v", err)
// 			}

// 			signKey, err = jwtGo.ParseECPrivateKeyFromPEM(signBytes)
// 			if err != nil {
// 				t.Errorf("Unable to parse ECDSA private key: %v", err)
// 			}

// 		default:
// 			t.Errorf("Unrecognized ECDSA alg: %s", data.alg)
// 		}

// 		cOptions := credentialsOptions{
// 			SigningMethodString: data.alg,
// 		}
// 		c := credentials{
// 			options: cOptions,
// 		}

// 		var claims ClaimsType
// 		claims.CustomClaims = data.customClaims

// 		tempToken := c.newTokenWithClaims(claims, data.validTime)

// 		tempTokenString, err := tempToken.Token.SignedString(signKey)
// 		if err != nil {
// 			t.Errorf("Unable to sign token with private key: %v", err)
// 		}

// 		if tempTokenString != data.tokenString && data.valid {
// 			t.Errorf("ECDSA token strings do not match at idx: %d; String: %s, Expected: %s", i, tempTokenString, data.tokenString)
// 		} else if tempTokenString == data.tokenString && !data.valid {
// 			t.Errorf("ECDSA token strings match but were not expected to at idx: %d; String: %s, Expected: %s", i, tempTokenString, data.tokenString)
// 		}
// 	}
// }

func TestBuildingHSFromClaims(t *testing.T) {
	var key = []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`)

	for i, data := range hsTestTokenStrings {
		cOptions := credentialsOptions{
			SigningMethodString: data.alg,
		}
		c := credentials{
			options: cOptions,
		}
		var claims ClaimsType
		claims.CustomClaims = data.customClaims

		tempToken := c.newTokenWithClaims(&claims, data.validTime)

		tempTokenString, err := tempToken.Token.SignedString(key)
		if err != nil {
			t.Errorf("Unable to sign token with private key: %v", err)
		}

		if tempTokenString != data.tokenString && data.valid {
			t.Errorf("HS token strings do not match at idx: %d; String: %s, Expected: %s", i, tempTokenString, data.tokenString)
		} else if tempTokenString == data.tokenString && !data.valid {
			t.Errorf("HS token strings match but were not expected to at idx: %d; String: %s, Expected: %s", i, tempTokenString, data.tokenString)
		}
	}
}

func TestUpdateTokenExpiry(t *testing.T) {
	var key = []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`)
	i := 0
	tempTime := time.Now().Unix()

	cOptions := credentialsOptions{
		SigningMethodString: hsTestTokenStrings[i].alg,
	}
	c := credentials{
		options: cOptions,
	}

	tempToken := c.buildTokenWithClaimsFromString(hsTestTokenStrings[i].tokenString, key, defaultAuthTokenValidTime)
	if tempToken.ParseErr != nil && hsTestTokenStrings[i].valid {
		t.Errorf("Unable to parse HS token string at idx: %d; Err: %v", i, tempToken.ParseErr)
	} else if tempToken.ParseErr == nil && !hsTestTokenStrings[i].valid {
		t.Errorf("Token parsed correctly, but is invalid at HS token string idx: %d", i)
	}

	err := tempToken.updateTokenExpiry()
	if err != nil {
		t.Errorf("Unable to update HS token expiry at idx: %d; Err: %v", i, err)
	}

	tempTokenClaims, ok := tempToken.Token.Claims.(*ClaimsType)
	if !ok {
		t.Errorf("Unable to read claims from HS token string at idx: %d; Claims: %v", i, tempToken.Token.Claims)
	}

	deltaT := tempTokenClaims.StandardClaims.ExpiresAt - tempTime
	if deltaT/int64(hsTestTokenStrings[i].validTime.Seconds()) > 1 {
		t.Errorf("HS token time not updated correctly at idx: %d; Delta T: %d; Valid Time: %d", i, deltaT, hsTestTokenStrings[i].validTime.Nanoseconds())
	}
}

func TestUpdateTokenCSRF(t *testing.T) {
	var key = []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`)
	i := 0
	s := "new csrf string"

	cOptions := credentialsOptions{
		SigningMethodString: hsTestTokenStrings[i].alg,
	}
	c := credentials{
		options: cOptions,
	}

	tempToken := c.buildTokenWithClaimsFromString(hsTestTokenStrings[i].tokenString, key, defaultAuthTokenValidTime)
	if tempToken.ParseErr != nil && hsTestTokenStrings[i].valid {
		t.Errorf("Unable to parse HS token string at idx: %d; Err: %v", i, tempToken.ParseErr)
	} else if tempToken.ParseErr == nil && !hsTestTokenStrings[i].valid {
		t.Errorf("Token parsed correctly, but is invalid at HS token string idx: %d", i)
	}

	err := tempToken.updateTokenCsrf(s)
	if err != nil {
		t.Errorf("Unable to update HS token expiry at idx: %d; Err: %v", i, err)
	}

	tempTokenClaims, ok := tempToken.Token.Claims.(*ClaimsType)
	if !ok {
		t.Errorf("Unable to read claims from HS token string at idx: %d; Claims: %v", i, tempToken.Token.Claims)
	}

	if tempTokenClaims.Csrf != s {
		t.Errorf("Unable to update token csrf from HS token string at ids: %d; Token Csrf: %s; Expected: %s", i, tempTokenClaims.Csrf, s)
	}
}

func TestUpdateTokenExpiryAndCsrf(t *testing.T) {
	var key = []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`)
	i := 0
	tempTime := time.Now().Unix()
	s := "new csrf string"

	cOptions := credentialsOptions{
		SigningMethodString: hsTestTokenStrings[i].alg,
	}
	c := credentials{
		options: cOptions,
	}

	tempToken := c.buildTokenWithClaimsFromString(hsTestTokenStrings[i].tokenString, key, defaultAuthTokenValidTime)
	if tempToken.ParseErr != nil && hsTestTokenStrings[i].valid {
		t.Errorf("Unable to parse HS token string at idx: %d; Err: %v", i, tempToken.ParseErr)
	} else if tempToken.ParseErr == nil && !hsTestTokenStrings[i].valid {
		t.Errorf("Token parsed correctly, but is invalid at HS token string idx: %d", i)
	}

	err := tempToken.updateTokenExpiryAndCsrf(s)
	if err != nil {
		t.Errorf("Unable to update HS token expiry at idx: %d; Err: %v", i, err)
	}

	tempTokenClaims, ok := tempToken.Token.Claims.(*ClaimsType)
	if !ok {
		t.Errorf("Unable to read claims from HS token string at idx: %d; Claims: %v", i, tempToken.Token.Claims)
	}

	deltaT := tempTokenClaims.StandardClaims.ExpiresAt - tempTime
	if deltaT/int64(hsTestTokenStrings[i].validTime.Seconds()) > 1 {
		t.Errorf("HS token time not updated correctly at idx: %d; Delta T: %d; Valid Time: %d", i, deltaT, hsTestTokenStrings[i].validTime.Nanoseconds())
	}
	if tempTokenClaims.Csrf != s {
		t.Errorf("Unable to update token csrf from HS token string at ids: %d; Token Csrf: %s; Expected: %s", i, tempTokenClaims.Csrf, s)
	}
}
