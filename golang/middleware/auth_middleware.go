package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type GatekeeperPayload struct {
	OrganizationName string `json:"organization_name"`
	Method           string `json:"method"`
	Path             string `json:"path"`
}

func AuthAndGatekeeper(gatekeeperURL string) func(http.Handler) http.Handler {
	client := &http.Client{}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Step 1: Extract and validate JWT token
			tokenData, errResp := extractToken(r)
			if errResp != nil {
				http.Error(w, errResp.Error(), errResp.StatusCode)
				return
			}

			// Step 2: Validate with gatekeeper
			validation, errResp := validateWithGatekeeper(client, gatekeeperURL, r, tokenData["realm"].(string))
			if errResp != nil {
				http.Error(w, errResp.Error(), errResp.StatusCode)
				return
			}

			// Add context
			ctx := context.WithValue(r.Context(), "realm", tokenData["realm"])
			ctx = context.WithValue(ctx, "token_payload", tokenData["payload"])
			ctx = context.WithValue(ctx, "validation", validation)

			// Proceed
			next.ServeHTTP(w, r.WithContext(ctx))

			// Step 3: Record usage
			go recordUsage(client, gatekeeperURL, r, tokenData["realm"].(string))
		})
	}
}

type ErrorResponse struct {
	Message    string
	StatusCode int
}

func (e *ErrorResponse) Error() string {
	return e.Message
}

func extractToken(r *http.Request) (map[string]interface{}, *ErrorResponse) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, &ErrorResponse{"Missing or invalid auth token", http.StatusUnauthorized}
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, &ErrorResponse{"Invalid token: " + err.Error(), http.StatusUnauthorized}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &ErrorResponse{"Invalid token payload", http.StatusUnauthorized}
	}

	realm, ok := claims["realm"].(string)
	if !ok || realm == "" {
		return nil, &ErrorResponse{"Missing 'realm' in token", http.StatusUnauthorized}
	}

	return map[string]interface{}{
		"realm":   realm,
		"payload": claims,
	}, nil
}

func validateWithGatekeeper(client *http.Client, gatekeeperURL string, r *http.Request, realm string) (map[string]interface{}, *ErrorResponse) {
	payload := GatekeeperPayload{
		OrganizationName: realm,
		Method:           r.Method,
		Path:             r.URL.Path,
	}

	data, _ := json.Marshal(payload)
	resp, err := client.Post(gatekeeperURL+"/validate", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, &ErrorResponse{"Gatekeeper error: " + err.Error(), http.StatusInternalServerError}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, &ErrorResponse{"Unauthorized by gatekeeper", http.StatusForbidden}
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	return result, nil
}

func recordUsage(client *http.Client, gatekeeperURL string, r *http.Request, realm string) {
	payload := GatekeeperPayload{
		OrganizationName: realm,
		Method:           r.Method,
		Path:             r.URL.Path,
	}

	data, _ := json.Marshal(payload)
	resp, err := client.Post(gatekeeperURL+"/recordUsage", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("Usage recorder error: %s\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Usage recording failed: %d %s\n", resp.StatusCode, resp.Status)
	}
}
