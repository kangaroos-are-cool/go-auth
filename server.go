package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var jwtKey = []byte(getEnv("JWT_KEY"))

// AppDetails ...
type AppDetails struct {
	BaseURL string
	AppPort string
}

// User ...
type User struct {
	Username string
	Hash     string
	Token    jwt.Token
}

// Claims ...
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func (a AppDetails) String() string {
	return fmt.Sprintf("App Running on: %v:%v", a.BaseURL, a.AppPort)
}

func hashAndSalt(password []byte) string {
	hash, err := bcrypt.GenerateFromPassword(password, 8)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

func compareHash(hashedPassword []byte, plainText []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPassword, plainText)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func getEnv(key string) string {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Could not load .env file")
	}

	return os.Getenv(key)
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		t, err := template.ParseFiles("templates/registration.html")
		if err != nil {
			log.Fatal("Could not load template")
		}
		//a := &AppDetails{getEnv("BASE_URL"), getEnv("APP_PORT")}
		t.Execute(w, nil)
	case "POST":
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		var data map[string]interface{}
		//fmt.Println(string(body))
		err = json.Unmarshal([]byte(string(body)), &data)
		if err != nil {
			panic(err)
		}
		//fmt.Fprintf(w, data["username"].(string))
		// need to hash password
		username := []byte(data["username"].(string))
		password := []byte(data["password"].(string))

		// connect to MongoDB client
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://"+getEnv("MONGO_HOST")+":"+getEnv("MONGO_PORT")))
		if err != nil {
			fmt.Println(err)
			log.Fatal("Could not connect to MongoDB client")
		}
		defer client.Disconnect(ctx)

		// if registration succeeded, alert it and redirect to login page

		userDatabase := client.Database("go-app-users")
		userCollection := userDatabase.Collection("users")

		// see if user already exists with these credentials
		var user bson.M
		err = userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
		//fmt.Println(user)
		if user != nil {
			fmt.Fprintf(w, "{\"Message\": \"A user with that username already exists\", \"Code\":409}")
		} else {
			// create user in DB
			hashedPassword := hashAndSalt(password)
			result, err := userCollection.InsertOne(ctx, bson.D{
				{Key: "username", Value: username},
				{Key: "password", Value: hashedPassword},
				{Key: "jwt", Value: ""},
			})

			if err != nil {
				fmt.Println(err)
				log.Fatal("Could not register user")
			}
			fmt.Println(result)
			fmt.Fprintf(w, "{\"Message\": \"You've successfully registered!\"}")

		}
	default:
		fmt.Fprintf(w, "Only GET and POST methods supported")
	}
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

	c, err := r.Cookie("token")
	//fmt.Println(c)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the JWT string from the cookie
	tknStr := c.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	t, err := template.ParseFiles("templates/secret.html")
	if err != nil {
		log.Fatal("Could not load template")
	}

	t.Execute(w, claims)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/login.html")
	if err != nil {
		log.Fatal("Could not load template")
	}

	switch r.Method {
	case "GET":
		a := &AppDetails{getEnv("BASE_URL"), getEnv("APP_PORT")}
		t.Execute(w, a)
	case "POST":
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		var data map[string]interface{}

		err = json.Unmarshal([]byte(string(body)), &data)
		if err != nil {
			panic(err)
		}

		// need to hash password
		username := []byte(data["username"].(string))
		password := []byte(data["password"].(string))

		// connect to MongoDB client
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://"+getEnv("MONGO_HOST")+":"+getEnv("MONGO_PORT")))
		if err != nil {
			log.Fatal("Could not connect to MongoDB client")
		}
		defer client.Disconnect(ctx)
		userDatabase := client.Database("go-app-users")
		userCollection := userDatabase.Collection("users")

		var result bson.M
		err = userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&result)
		if err != nil {
			fmt.Fprintf(w, "No such user found")
			return
		}

		if compareHash([]byte(result["password"].(string)), password) {
			fmt.Println("Successful Login")
			// generate JWT for user
			expirationTime := time.Now().Add(15 * time.Second)
			claims := &Claims{
				Username: string(username),
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: expirationTime.Unix(),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(jwtKey)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// set JWT token for user
			http.SetCookie(w, &http.Cookie{
				Name:    "token",
				Value:   tokenString,
				Expires: expirationTime,
			})

			// update Mongodb to hold JWT token
			userCollection.FindOneAndUpdate(ctx, bson.M{"username": username}, bson.M{"$set": bson.M{"jwt": tokenString}})

		} else {
			//fmt.Println("Invalid credentials")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	default:
		fmt.Fprintf(w, "Only GET and POST methods supported")
	}

}

func main() {
	// register handlers
	http.HandleFunc("/register", registrationHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/secret", secretHandler)
	http.HandleFunc("/", homeHandler)

	fmt.Println("Small web app with go-based backend for learning go and having fun")
	fmt.Println(&AppDetails{getEnv("BASE_URL"), getEnv("APP_PORT")})

	//log.Fatal(http.ListenAndServe(":"+getEnv("APP_PORT"), nil))
	log.Fatal(http.ListenAndServeTLS(":"+getEnv("APP_PORT"), "server.crt", "server.key", nil))
}
