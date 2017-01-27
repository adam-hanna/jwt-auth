package handlers

import (
	"github.com/justinas/alice"
	"log"
	"net/http"
	"strings"
	"time"

	"../../db"
	"../templates"
	"github.com/adam-hanna/jwt-auth/jwt"
)

var restrictedRoute jwt.Auth

// InitHandlers : initialize all of our handlers
func InitHandlers() error {
	newRouteError := jwt.New(&restrictedRoute, jwt.Options{
		SigningMethodString:   "RS256",
		PrivateKeyLocation:    "keys/app.rsa",     // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation:     "keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    15 * time.Minute,
		Debug:                 true,
		IsDevEnv:              true,
	})
	if newRouteError != nil {
		return newRouteError
	}

	restrictedRoute.SetUnauthorizedHandler(MyUnauthorizedHandler)
	restrictedRoute.SetErrorHandler(myErrorHandler)

	restrictedRoute.SetRevokeTokenFunction(db.DeleteRefreshToken)
	restrictedRoute.SetCheckTokenIdFunction(db.CheckRefreshToken)

	http.Handle("/", alice.New(recoverHandler).ThenFunc(loginHandler))
	http.Handle("/register", alice.New(recoverHandler).ThenFunc(registerHandler))

	http.Handle("/restricted", alice.New(restrictedRoute.Handler, recoverHandler).ThenFunc(restrictedHandler))
	http.Handle("/logout", alice.New(restrictedRoute.Handler, recoverHandler).ThenFunc(logoutHandler))
	http.Handle("/deleteUser", alice.New(restrictedRoute.Handler, recoverHandler).ThenFunc(deleteUserHandler))

	return nil
}

// MyUnauthorizedHandler : custom 401
var MyUnauthorizedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "I pitty the fool who is unauthorized", 401)
})

var myErrorHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "I pitty the fool who has a 500 internal server error", 500)
})

func recoverHandler(next http.Handler) http.Handler {
	// this catches any errors and returns an internal server error to the client
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panicf("Recovered! Panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

var restrictedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	csrfSecret := w.Header().Get("X-CSRF-Token")
	templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{csrfSecret, "Stoofs!"})
})

var loginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		templates.RenderTemplate(w, "login", &templates.LoginPage{false, ""})

	case "POST":
		r.ParseForm()
		log.Println(r.Form)

		user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
		log.Println(user, uuid, loginErr)
		if loginErr != nil {
			// login err
			// templates.RenderTemplate(w, "login", &templates.LoginPage{ true, "Login failed\n\nIncorrect username or password" })
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			// no login err
			// now generate credentials for this user
			claimsId, idErr := db.StoreRefreshToken()
			if idErr != nil {
				http.Error(w, http.StatusText(500), 500)
			}

			claims := jwt.ClaimsType{}
			claims.StandardClaims.Subject = uuid
			claims.StandardClaims.Id = claimsId
			claims.CustomClaims = make(map[string]interface{})
			claims.CustomClaims["Role"] = user.Role

			err := restrictedRoute.IssueNewTokens(w, &claims)
			if err != nil {
				http.Error(w, "Internal Server Error", 500)
			}

			w.WriteHeader(http.StatusOK)
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
})

var registerHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		templates.RenderTemplate(w, "register", &templates.RegisterPage{false, ""})

	case "POST":
		r.ParseForm()
		log.Println(r.Form)

		// check to see if the username is already taken
		_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
		if err == nil {
			templates.RenderTemplate(w, "register", &templates.RegisterPage{true, "Username not available!"})
			// w.WriteHeader(http.StatusUnauthorized)
		} else {
			// nope, now create this user
			role := "user"
			uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
			}
			log.Println("uuid: " + uuid)

			// now generate cookies for this user
			claimsId, idErr := db.StoreRefreshToken()
			if idErr != nil {
				http.Error(w, http.StatusText(500), 500)
			}

			claims := jwt.ClaimsType{}
			claims.StandardClaims.Subject = uuid
			claims.StandardClaims.Id = claimsId
			claims.CustomClaims = make(map[string]interface{})
			claims.CustomClaims["Role"] = role

			err := restrictedRoute.IssueNewTokens(w, &claims)
			if err != nil {
				http.Error(w, "Internal Server Error", 500)
			}

			w.WriteHeader(http.StatusOK)
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
})

var logoutHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// remove this user's ability to make requests
	err := restrictedRoute.NullifyTokens(w, r)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}
	// use 302 to force browser to do GET request
	http.Redirect(w, r, "/", 302)
})

var deleteUserHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	log.Println("Deleting user")

	claims, claimsErr := restrictedRoute.GrabTokenClaims(r)
	if claimsErr != nil {
		http.Error(w, http.StatusText(500), 500)
	} else {
		db.DeleteUser(claims.StandardClaims.Subject)
		// remove this user's ability to make requests
		err := restrictedRoute.NullifyTokens(w, r)
		if err != nil {
			http.Error(w, "Internal Server Error", 500)
			return
		}
		// use 302 to force browser to do GET request
		http.Redirect(w, r, "/register", 302)
	}
})
