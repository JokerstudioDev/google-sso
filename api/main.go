package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	oauth2 "google.golang.org/api/oauth2/v1"
)

func main() {

	// Here we are instantiating the gorilla/mux router
	r := mux.NewRouter()

	r.Handle("/health", HealthHandler).Methods("GET", "OPTIONS")
	r.Handle("/profile", googleMiddlewareHandler(ProfileHandler)).Methods("POST", "OPTIONS")

	// Our application will run on port 3000. Here we declare the port and pass in our router.
	http.ListenAndServe(":3000", handlers.LoggingHandler(os.Stdout, r))
}

var httpClient = &http.Client{}

func verifyIdToken(idToken string) (*oauth2.Tokeninfo, error) {
	oauth2Service, err := oauth2.New(httpClient)
	tokenInfoCall := oauth2Service.Tokeninfo()
	tokenInfoCall.IdToken(idToken)
	tokenInfo, err := tokenInfoCall.Do()
	if err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func googleMiddlewareHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//Define CORS
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

		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		reqToken := r.Header.Get("Authorization")
		splitToken := strings.Split(reqToken, "Bearer ")
		reqToken = splitToken[1]
		tokenInfo, err := verifyIdToken(reqToken)

		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("{\"error\": \"invalid token\"}"))
			return
		} else {
			newRequest := r.WithContext(context.WithValue(r.Context(), "tokeninfo", tokenInfo))
			*r = *newRequest
			h.ServeHTTP(w, r)
		}
	})
}

var HealthHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API is up and running"))
})

var ProfileHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token, _ := ctx.Value("tokeninfo").(*oauth2.Tokeninfo)
	fmt.Println(token.Email)
	response, _ := json.Marshal(token)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response))
})
