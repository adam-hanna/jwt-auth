package templates

import (
	"html/template"
	"log"
	"net/http"
)

// LoginPage : the login page
type LoginPage struct {
}

// RestrictedPage : the secret page
type RestrictedPage struct {
	CsrfSecret string
	Role       string
}

var templates = template.Must(template.ParseFiles("./templates/templateFiles/login.tmpl"))

// RenderTemplate : apply the given template to the responsewriter
func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".tmpl", p)
	if err != nil {
		log.Printf("Temlate error here: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
