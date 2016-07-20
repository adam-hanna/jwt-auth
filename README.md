# jwt-auth
jwt auth middleware in goLang


## Quickstart
~~~ go
package main

import (
	"net/http"
	"log"
	"time"

	"github.com/adam-hanna/jwt-auth/jwt"
)

var restrictedRoute jwt.Auth

var restrictedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the secret area!"))
})

var regularHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, World!"))
})

func main() {
	authErr := jwt.New(&restrictedRoute, jwt.Options{
		PrivateKeyLocation: 	"keys/app.rsa", // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation: 		"keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 	72 * time.Hour,
		AuthTokenValidTime: 	15 * time.Minute,
		Debug: 					false,
	})
	if authErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(authErr)
	}

	http.HandleFunc("/", regularHandler)
	// this will never be available because we never issue tokens
	// see login_logout example for how to provide tokens
	http.Handle("/restricted", restrictedRoute.Handler(restrictedHandler))

	log.Println("Listening on localhost:3000")
	http.ListenAndServe("127.0.0.1:3000", nil)
}
~~~

## Goals
It is important to understand the objective of this auth architecture. It certainly is not an applicable design for all use cases. Please read and understand the goals, below, and make changes to your own workflow to suit your specific needs.

1. Protection of non-critical api's (e.g. not meant for financial, healthcare, gov't, etc. services)
2. Stateless
3. User sessions
4. XSS protection
5. CSRF protection
6. Web (but could be easily modified for use in mobile / other. i.e. for native mobile don't use cookies but rather the proper, secure storage methods for your platform)

## Basics
The design of this auth system is based around the three major components, listed below.

1. Short-lived (minutes) JWT Auth Token
2. Longer-lived (hours / days) JWT Refresh Token
3. CSRF secret string

### 1. Short-lived (minutes) JWT Auth Token
The short-lived jwt auth token allows the user to make stateless requests to protected api endpoints and lives in an http only cookie on the client. It has an expiration time of 15 minutes by default and will be refreshed by the longer-lived refresh token. 

### 2. Longer-lived (hours/days) JWT Refresh Token
This longer-lived token will be used to update the auth tokens. These tokens will also live in http only cookies on the client. These tokens have a 72 hour expiration time by default which will be updated each time an auth token is refreshed.

These refresh tokens contain an id which can be revoked by an authorized client.

### 3. CSRF Secret String
A CSRF secret string will be provided to each client and will be identical the CSRF secret in the auth and refresh tokens and will change each time an auth token is refreshed. These secrets will live in an "X-CSRF-Token" response header. These secrets will be sent along with the auth and refresh tokens on each api request. 

When request are made to protected endpoint, these CSRF secrets need to be sent to the server either as a hidden form value with a name of "X-CSRF-Token" or in the request header with the key of "X-CSRF-Token". This secret will be checked against the secret provided in the auth token in order to prevent CSRF attacks.

## API

### Create a new jwt middleware
~~~ go
var restrictedRoute jwt.Auth
~~~

### JWT middleware options
~~~ go
type Options struct {
	PrivateKeyLocation 		string
	PublicKeyLocation 		string
	RefreshTokenValidTime 	time.Duration
	AuthTokenValidTime 		time.Duration
	Debug 					bool
	TokenClaims 			ClaimsType
}
~~~

### ClaimsType
~~~ go
type ClaimsType struct {
	// Standard claims are the standard jwt claims from the ietf standard
	// https://tools.ietf.org/html/rfc7519
	jwt.StandardClaims
	Csrf 				string
	CustomClaims 		map[string]interface{}
}
~~~

You don't have to worry about any of this, except know that there is a "CustomClaims" map that allows you to set whatever you want. See "IssueTokenClaims" and "GrabTokenClaims", below, for more.

### Initialize new JWT middleware
~~~ go
authErr := jwt.New(&restrictedRoute, jwt.Options{
	PrivateKeyLocation: 	"keys/app.rsa", // `$ openssl genrsa -out app.rsa 2048`
	PublicKeyLocation: 		"keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
	RefreshTokenValidTime: 	72 * time.Hour,
	AuthTokenValidTime: 	15 * time.Minute,
	Debug: 					false,
})
if authErr != nil {
	log.Println("Error initializing the JWT's!")
	log.Fatal(authErr)
}
~~~

### Handle a restricted route (see below for integration with popular frameworks)
~~~ go
// outside of main()
var restrictedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	csrfSecret := w.Header().Get("X-CSRF-Token")
	claims, err := restrictedRoute.GrabTokenClaims(w, r)
	log.Println(claims)
	
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
	} else {
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{ csrfSecret, claims.CustomClaims["Role"].(string) })
	}
})

func main() {
	...
	http.Handle("/restricted", restrictedRoute.Handler(restrictedHandler))

	log.Println("Listening on localhost:3000")
	http.ListenAndServe("127.0.0.1:3000", nil)
}
~~~

### Issue new tokens and CSRF secret (for instance, when a user provides valid login credentials)
~~~ go
// in a handler func
claims := jwt.ClaimsType{}
claims.CustomClaims = make(map[string]interface{})
claims.CustomClaims["Role"] = "user"

err := restrictedRoute.IssueNewTokens(w, claims)
if err != nil {
	http.Error(w, "Internal Server Error", 500)
}

w.WriteHeader(http.StatusOK)
~~~

### Get a CSRF secret from a response
~~~ go
// in a handler func
// note: this works because if the middleware has made it this far, the JWT middleware has written a CSRF secret to the response writer (w)
csrfSecret := w.Header().Get("X-CSRF-Token")
~~~

### Get claims from a request
~~~ go
// in a handler func
claims, err := restrictedRoute.GrabTokenClaims(w, r)
log.Println(claims)
~~~

### Nullify auth and refresh tokens (for instance, when a user logs out)
~~~ go
// in a handler func
restrictedRoute.NullifyTokenCookies(&w, r)
http.Redirect(w, r, "/login", 302)
~~~

### Token Id checker
A function used to check a refresh token id against a list of revoked (or blacklisted) id's. Returns true if the token id has not been revoked. This function is run everytime an auth token is refreshed.
~~~go
type TokenIdChecker func(tokenId string) bool

func defaultCheckTokenId(tokenId string) bool {
	// return true if the token id is valid (has not been revoked). False for otherwise
	return true
}

func (a *Auth) SetCheckTokenIdFunction(checker TokenIdChecker) {
	a.checkTokenId = checker
}
~~~

### Token Id revoker
A function that adds a token id to a blacklist of revoked tokens.
~~~go
type TokenRevoker func(tokenId string) error

func defaultTokenRevoker(tokenId string) error {
	return nil
}

func (a *Auth) SetRevokeTokenFunction(revoker TokenRevoker) {
	a.revokeRefreshToken = revoker
}
~~~

### 500 error handling
Set the response to a 500 error.
~~~go
func defaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", 500)
}

func (a *Auth) SetErrorHandler(handler http.Handler) {
	a.errorHandler = handler
}
~~~

### 401 unauthorized handling
Set the response to a 401 unauthorized request
~~~go
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unauthorized", 401)
}

func (a *Auth) SetUnauthorizedHandler(handler http.Handler) {
	a.unauthorizedHandler = handler
}
~~~


## Integration with popular goLang web Frameworks (untested)

The architecture of this package was inspired by [Secure](https://github.com/unrolled/secure), so I believe the integrations, below, should work. But they are untested.

### [Echo](https://github.com/labstack/echo)
~~~ go
// main.go
package main

import (
    "net/http"
    "log"

    "github.com/labstack/echo"
    "github.com/adam-hanna/jwt-auth/jwt"
)

var restrictedRoute jwt.Auth

func main() {
    authErr := jwt.New(&restrictedRoute, jwt.Options{
		PrivateKeyLocation: 	"keys/app.rsa", // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation: 		"keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 	72 * time.Hour,
		AuthTokenValidTime: 	15 * time.Minute,
		Debug: 					false,
	})
	if authErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(authErr)
	}

    e := echo.New()

    e.Get("/", func(c *echo.Context) error {
        c.String(http.StatusOK, "Restricted")
        return nil
    })
    e.Use(restrictedRoute.Handler)

    e.Run("127.0.0.1:3000")
}
~~~

### [Gin](https://github.com/gin-gonic/gin)
~~~ go
// main.go
package main

import (
    "log"

    "github.com/gin-gonic/gin"
    "github.com/adam-hanna/jwt-auth/jwt"
)

var restrictedRoute jwt.Auth

func main() {
    authErr := jwt.New(&restrictedRoute, jwt.Options{
		PrivateKeyLocation: 	"keys/app.rsa", // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation: 		"keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 	72 * time.Hour,
		AuthTokenValidTime: 	15 * time.Minute,
		Debug: 					false,
	})
	if authErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(authErr)
	}
    restrictedFunc := func() gin.HandlerFunc {
        return func(c *gin.Context) {
            err := restrictedRoute.Process(c.Writer, c.Request)

            // If there was an error, do not continue.
            if err != nil {
                return
            }

            c.Next()
        }
    }()

    router := gin.Default()
    router.Use(restrictedFunc)

    router.GET("/", func(c *gin.Context) {
        c.String(200, "Restricted")
    })

    router.Run("127.0.0.1:3000")
}
~~~

### [Goji](https://github.com/zenazn/goji)
~~~ go
// main.go
package main

import (
    "net/http"
    "log"

    "github.com/adam-hanna/jwt-auth/jwt"
    "github.com/zenazn/goji"
    "github.com/zenazn/goji/web"
)

var restrictedRoute jwt.Auth

func main() {
    authErr := jwt.New(&restrictedRoute, jwt.Options{
		PrivateKeyLocation: 	"keys/app.rsa", // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation: 		"keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 	72 * time.Hour,
		AuthTokenValidTime: 	15 * time.Minute,
		Debug: 					false,
	})
	if authErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(authErr)
	}

    goji.Get("/", func(c web.C, w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("Restricted"))
    })
    goji.Use(restrictedRoute.Handler)
    goji.Serve() // Defaults to ":8000".
}
~~~

### [Iris](https://github.com/kataras/iris)
~~~ go
//main.go
package main

import (
    "log"

	"github.com/kataras/iris"
	"github.com/adam-hanna/jwt-auth/jwt"
)

var restrictedRoute jwt.Auth

func main() {
	authErr := jwt.New(&restrictedRoute, jwt.Options{
		PrivateKeyLocation: 	"keys/app.rsa", // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation: 		"keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 	72 * time.Hour,
		AuthTokenValidTime: 	15 * time.Minute,
		Debug: 					false,
	})
	if authErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(authErr)
	}

	iris.UseFunc(func(c *iris.Context) {
		err := restrictedRoute.Process(c.ResponseWriter, c.Request)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		c.Next()
	})

	iris.Get("/home", func(c *iris.Context) {
		c.SendStatus(200,"Restricted")
	})

	iris.Listen(":8080")

}

~~~~

### [Negroni](https://github.com/codegangsta/negroni)
Note this implementation has a special helper function called `HandlerFuncWithNext`.
~~~ go
// main.go
package main

import (
    "net/http"
    "log"

    "github.com/codegangsta/negroni"
    "github.com/adam-hanna/jwt-auth/jwt"
)

var restrictedRoute jwt.Auth

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("Restricted"))
    })

    authErr := jwt.New(&restrictedRoute, jwt.Options{
		PrivateKeyLocation: 	"keys/app.rsa", // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation: 		"keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 	72 * time.Hour,
		AuthTokenValidTime: 	15 * time.Minute,
		Debug: 					false,
	})
	if authErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(authErr)
	}

    n := negroni.Classic()
    n.Use(negroni.HandlerFunc(restrictedRoute.HandlerFuncWithNext))
    n.UseHandler(mux)

    n.Run("127.0.0.1:3000")
}
~~~