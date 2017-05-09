package main

import (
	"./templates"
	"github.com/adam-hanna/jwt-auth/jwt"

	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var restrictedRoute jwt.Auth
var authRoute jwt.Auth

var myUnauthorizedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// tokens are invalid, so we need to ask our auth server for new ones
	req, err := http.NewRequest("GET", "http://localhost:3001/refreshClaims", nil)
	if err != nil {
		log.Println("Err building refresh credentials request", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
	AuthCookie, authErr := r.Cookie("AuthToken")
	if authErr == http.ErrNoCookie {
		log.Println("No auth cookie")
		http.Error(w, "I Pitty the fool who is Unauthorized", 401)
		return
	} else if authErr != nil {
		log.Println("Error grabbing the auth cookie", authErr)
		http.Error(w, "Internal server error", 500)
		return
	}
	req.AddCookie(AuthCookie)

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		log.Println("No refresh cookie")
		http.Error(w, "I Pitty the fool who is Unauthorized", 401)
		return
	} else if refreshErr != nil {
		log.Println("Error grabbing the refresh cookie", refreshErr)
		http.Error(w, "Internal server error", 500)
		return
	}
	req.AddCookie(RefreshCookie)

	csrfSecret := r.FormValue("X-CSRF-Token")
	if csrfSecret == "" {
		csrfSecret = r.Header.Get("X-CSRF-Token")
	}
	req.Header.Add("X-CSRF-Token", csrfSecret)

	// send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Err calling calling auth server", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	if resp.StatusCode == 200 {
		// jwts have been refreshed, now make the call again to the original resource
		rc := resp.Cookies()
		var authCookieIndex int
		var refreshCookieIndex int

		for i, cookie := range rc {
			if cookie.Name == "AuthToken" {
				authCookieIndex = i
			}
			if cookie.Name == "RefreshToken" {
				refreshCookieIndex = i
			}
		}

		req2, err := http.NewRequest("POST", "http://"+r.Host+r.URL.Path, nil)
		if err != nil {
			log.Println("Err building refresh credentials request", err)
			http.Error(w, "Internal Server Error", 500)
			return
		}
		req2.AddCookie(rc[authCookieIndex])
		req2.AddCookie(rc[refreshCookieIndex])
		req2.Header.Add("X-CSRF-Token", resp.Header.Get("X-CSRF-Token"))

		// send the request
		client2 := &http.Client{}
		resp2, err := client2.Do(req2)
		if err != nil {
			log.Println("Err calling original resource", err)
			http.Error(w, "Internal Server Error", 500)
			return
		}

		rc2 := resp2.Cookies()
		authCookieIndex2 := -1
		refreshCookieIndex2 := -1
		for i, cookie := range rc2 {
			if cookie.Name == "AuthToken" {
				authCookieIndex2 = i
			}
			if cookie.Name == "RefreshToken" {
				refreshCookieIndex2 = i
			}
		}

		if authCookieIndex2 >= 0 {
			http.SetCookie(w, rc2[authCookieIndex2])
		}
		if refreshCookieIndex2 >= 0 {
			http.SetCookie(w, rc2[refreshCookieIndex2])
		}

		w.Header().Set("X-CSRF-Token", resp2.Header.Get("X-CSRF-Token"))
		w.Header().Set("Auth-Expiry", resp2.Header.Get("Auth-Expiry"))
		w.Header().Set("Refresh-Expiry", resp2.Header.Get("Refresh-Expiry"))

		for k, v := range resp2.Header {
			w.Header().Set(k, strings.Join(v, ""))
		}

		w.WriteHeader(resp2.StatusCode)

		defer resp2.Body.Close()
		body, err := ioutil.ReadAll(resp2.Body)

		if err != nil {
			http.Error(w, "Internal server error", 500)
			return
		}

		w.Write(body)
		return
	} else if resp.StatusCode/100 == 4 {
		http.Error(w, "I Pitty the fool who is Unauthorized", 401)
		return
	} else {
		http.Error(w, "Internal server error", 500)
		return
	}
})

var restrictedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, err := restrictedRoute.GrabTokenClaims(r)
	log.Println(claims)

	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{claims.Csrf, claims.CustomClaims["Role"].(string)})
})

var issueClaimsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Expose-Headers", "X-CSRF-Token, Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Auth-Expiry, Refresh-Expiry")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "X-CSRF-Token, Origin, X-Requested-With, Content-Type, Accept, Authorization")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")

	switch r.Method {
	case "POST":
		r.ParseForm()

		if strings.Join(r.Form["username"], "") == "testUser" && strings.Join(r.Form["password"], "") == "testPassword" {
			log.Println("Correct credentials")
			claims := jwt.ClaimsType{}
			claims.CustomClaims = make(map[string]interface{})
			claims.CustomClaims["Role"] = "user"

			err := authRoute.IssueNewTokens(w, &claims)
			if err != nil {
				http.Error(w, "Internal Server Error", 500)
				return
			}

			log.Println("Successful login")
			w.WriteHeader(http.StatusOK)

		} else {
			http.Error(w, "Unauthorized", 401)
		}
	case "OPTIONS":
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, POST")
	default:
		http.Error(w, "Method Not Allowed", 405)
	}
})

var refreshClaimsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Expose-Headers", "X-CSRF-Token, Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Auth-Expiry, Refresh-Expiry")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "X-CSRF-Token, Origin, X-Requested-With, Content-Type, Accept, Authorization")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")

	switch r.Method {
	case "GET":
		fallthrough
	case "POST":
		// everything is done by the middleware
		// if it gets here, the cookies have refreshed
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.WriteHeader(http.StatusOK)

	case "OPTIONS":
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, POST, GET")
	default:
		http.Error(w, "Method Not Allowed", 405)
	}
})

var loginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		templates.RenderTemplate(w, "login", &templates.LoginPage{})

	default:
		http.Error(w, "Method Not Allowed", 405)
	}
})

var logoutHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		log.Println("In logout post")
		err := restrictedRoute.NullifyTokens(w, r)
		if err != nil {
			http.Error(w, "Internal Server Error", 500)
			return
		}

		http.Redirect(w, r, "/login", 302)

	default:
		http.Error(w, "Method Not Allowed", 405)
	}
})

func main() {
	jwtErr := jwt.New(&authRoute, jwt.Options{
		SigningMethodString:   "RS256",
		PrivateKeyLocation:    "keys/app.rsa",     // `$ openssl genrsa -out app.rsa 2048`
		PublicKeyLocation:     "keys/app.rsa.pub", // `$ openssl rsa -in app.rsa -pubout > app.rsa.pub`
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    5 * time.Second,
		Debug:                 true,
		IsDevEnv:              true,
	})
	if jwtErr != nil {
		log.Println("Error initializing authRoute JWT's!")
		log.Fatal(jwtErr)
	}
	jwtErr = jwt.New(&restrictedRoute, jwt.Options{
		SigningMethodString: "RS256",
		VerifyOnlyServer:    true,
		PublicKeyLocation:   "keys/app.rsa.pub",
		Debug:               true,
		IsDevEnv:            true,
	})
	if jwtErr != nil {
		log.Println("Error initializing restrictedRoute JWT's!")
		log.Fatal(jwtErr)
	}

	authMux := http.NewServeMux()
	authMux.HandleFunc("/issueClaims", issueClaimsHandler)
	authMux.Handle("/refreshClaims", authRoute.Handler(refreshClaimsHandler))
	go func() {
		log.Println("Auth route listening on localhost:3001")
		http.ListenAndServe("localhost:3001", authMux)
	}()

	restrictedMux := http.NewServeMux()
	restrictedRoute.SetUnauthorizedHandler(myUnauthorizedHandler)
	restrictedMux.HandleFunc("/", loginHandler)
	restrictedMux.Handle("/restricted", restrictedRoute.Handler(restrictedHandler))
	restrictedMux.Handle("/logout", restrictedRoute.Handler(logoutHandler))

	log.Println("Restricted route listening on localhost:3000")
	http.ListenAndServe("127.0.0.1:3000", restrictedMux)
}
