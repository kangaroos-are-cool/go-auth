package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
)

// AppDetails ...
type AppDetails struct {
	BaseURL string
	AppPort string
}

// User ...
type User struct {
	Email string
	Token jwt.Token
}

func (a AppDetails) String() string {
	return fmt.Sprintf(" BaseURL: %v, App Port: %v", a.BaseURL, a.AppPort)
}

func getEnv(key string) string {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Could not load .env file")
	}

	return os.Getenv(key)
}

func renderTemplate(w http.ResponseWriter, r *http.Request, temp string) {
	t, err := template.ParseFiles("/templates/" + temp + ".html")
	if err != nil {
		log.Fatal("Could not load template")
	}
	t.Execute(w, nil)
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/registration.html")
	if err != nil {
		log.Fatal("Could not load template")
	}
	title := "this is a page"
	t.Execute(w, title)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Fatal("Could not load template")
	}
	a := &AppDetails{getEnv("BASE_URL"), getEnv("APP_PORT")}
	t.Execute(w, a)
}

func secretHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/secret.html")
	if err != nil {
		log.Fatal("Could not load template")
	}
	a := &AppDetails{getEnv("BASE_URL"), getEnv("APP_PORT")}
	t.Execute(w, a)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/login.html")
	if err != nil {
		log.Fatal("Could not load template")
	}
	t.Execute(w, nil)
}

func main() {
	// register handlers
	http.HandleFunc("/register", registrationHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/secret", secretHandler)
	http.HandleFunc("/", homeHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
