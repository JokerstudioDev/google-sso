package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
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

var myAudience = "135057060926-gnm5fuukant99g0j94mun356aujugdum.apps.googleusercontent.com"
var issuer = "accounts.google.com"

func main() {

	// Here we are instantiating the gorilla/mux router
	r := mux.NewRouter()

	r.Handle("/health", HealthHandler).Methods("GET", "OPTIONS")
	r.Handle("/profile", googleMiddlewareHandler(ProfileHandler)).Methods("POST", "OPTIONS")

	// Our application will run on port 3000. Here we declare the port and pass in our router.
	http.ListenAndServe(":3000", handlers.LoggingHandler(os.Stdout, r))
}

var httpClient = &http.Client{}

func verifyIDToken(idToken string) (*auth.Token, error) {
	opt := option.WithCredentialsFile("./serviceAccountKey.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	client, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	token, err := client.VerifyIDToken(idToken)
	if err != nil {
		log.Fatalf("error verifying ID token: %v\n", err)
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
			newRequest := r.WithContext(context.WithValue(r.Context(), "user", user))
			*r = *newRequest
			h.ServeHTTP(w, r)
		}
	})
}

// Decode returns tokenInfo
func Decode(token string) (*Tokeninfo, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, errors.New("Invalid token received")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])

	if err != nil {
		return nil, err
	}
	tokenInfo := new(Tokeninfo)
	err = json.Unmarshal(decoded, &tokenInfo)
	return tokenInfo, err
}

// HealthHandler return api health
var HealthHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API is up and running"))
})

// ProfileHandler return profile info in token
var ProfileHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := ctx.Value("user").(User)
	response, _ := json.Marshal(user)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response))
})

//Tokeninfo extracted from id_token
type Tokeninfo struct {
	// AccessType: The access type granted with this token. It can be
	// offline or online.
	AccessType string `json:"access_type,omitempty"`

	// Audience: Who is the intended audience for this token. In general the
	// same as issued_to.
	Audience string `json:"aud,omitempty"`

	// Email: The email address of the user. Present only if the email scope
	// is present in the request.
	Email string `json:"email,omitempty"`

	// EmailVerified: Boolean flag which is true if the email address is
	// verified. Present only if the email scope is present in the request.
	EmailVerified bool `json:"email_verified,omitempty"`

	// ExpiresIn: The expiry time of the token, as number of seconds left
	// until expiry.
	ExpiresIn int64 `json:"exp,omitempty"`

	// IssuedAt: The issue time of the token, as number of seconds.
	IssuedAt int64 `json:"ist,omitempty"`

	// Issuer: Who issued the token.
	Issuer string `json:"iss,omitempty"`

	Sub string `json:"sub,omitempty"`

	Name string `json:"name,omitempty"`

	Picture string `json:"picture,omitempty"`

	GivenName string `json:"given_name,omitempty"`

	FamilyName string `json:"family_name,omitempty"`

	Locale string `json:"locale,omitempty"`
}

//User informations
type User struct {
	UserID        string `json:"user_id"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}
