package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	authMiddleware "go-app/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(authMiddleware.AuthAndGatekeeper("http://localhost:8082/gatekeeper"))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		realm := r.Context().Value("realm")
		validation := r.Context().Value("validation")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    "Hello World",
			"realm":      realm,
			"validation": validation,
		})
	})

	r.Get("/question", questionHandler)
	r.Post("/question", questionHandler)

	http.ListenAndServe(":8000", r)
}

func questionHandler(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value("token_payload")
	validation := r.Context().Value("validation")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "This is a validated /question endpoint.",
		"token_payload": payload,
		"validation":    validation,
	})
}
