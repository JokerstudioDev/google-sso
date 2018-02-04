package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/context"

	"firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"google.golang.org/api/option"
)

type Key uint8

var UserKey Key

func main() {

	// Here we are instantiating the gorilla/mux router
	r := mux.NewRouter()

	r.Handle("/health", HealthHandler).Methods("GET", "OPTIONS")
	r.Handle("/profile", googleMiddlewareHandler(ProfileHandler)).Methods("POST", "OPTIONS")

	// Our application will run on port 3000. Here we declare the port and pass in our router.
	http.ListenAndServe(":3000", handlers.LoggingHandler(os.Stdout, r))
}

func verifyIDToken(idToken string) (*auth.Token, error) {
	opt := option.WithCredentialsFile("./serviceAccountKey.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, err
	}

	token, err := client.VerifyIDToken(idToken)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func googleMiddlewareHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//Define CORS response
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers",
				"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		}
		// Stop here if its Preflighted OPTIONS request
		if r.Method == "OPTIONS" {
			return
		}

		reqToken := r.Header.Get("Authorization")
		splitToken := strings.Split(reqToken, "Bearer ")
		reqToken = splitToken[1]
		tokenInfo, err := verifyIDToken(reqToken) // if you want to verify yourself Decode(reqToken)

		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("{\"error\": \"invalid token\"}"))
		} else {
			user := User{
				UserID:        tokenInfo.Claims["user_id"].(string),
				Email:         tokenInfo.Claims["email"].(string),
				EmailVerified: tokenInfo.Claims["email_verified"].(bool),
				Name:          tokenInfo.Claims["name"].(string),
				Picture:       tokenInfo.Claims["picture"].(string),
			}
			newRequest := r.WithContext(context.WithValue(r.Context(), UserKey, user))
			*r = *newRequest
			h.ServeHTTP(w, r)
		}
	})
}

// HealthHandler return api health
var HealthHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API is up and running"))
})

// ProfileHandler return profile info in token
var ProfileHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := ctx.Value(UserKey).(User)
	response, _ := json.Marshal(user)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response))
})

//User informations
type User struct {
	UserID        string `json:"user_id"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}
