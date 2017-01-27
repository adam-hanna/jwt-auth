package templates

import (
	"html/template"
	"log"
	"net/http"
)

// LoginPage : the login page
type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

// RegisterPage : the register page
type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

// RestrictedPage : the restricted page
type RestrictedPage struct {
	CsrfSecret    string
	SecretMessage string
}

var templates = template.Must(template.ParseFiles("./server/templates/templateFiles/login.tmpl", "./server/templates/templateFiles/register.tmpl", "./server/templates/templateFiles/restricted.tmpl"))

// RenderTemplate : apply the given template to the response writer
func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".tmpl", p)
	if err != nil {
		log.Printf("Temlate error here: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
