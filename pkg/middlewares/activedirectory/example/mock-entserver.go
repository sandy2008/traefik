package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// Mock entserver-activedirectory service for testing
type EntitlementRequest struct {
	UserID string `json:"userID"`
	EonID  string `json:"eonID"`
	Env    string `json:"env"`
	Action string `json:"action"`
}

type EntitlementResponse struct {
	Entitled bool   `json:"entitled"`
	Message  string `json:"message,omitempty"`
}

// Mock user database
var authorizedUsers = map[string]map[string]bool{
	"alice": {
		"EON-123456:production:read":  true,
		"EON-123456:production:write": false,
		"EON-123456:production:admin": false,
	},
	"bob": {
		"EON-123456:production:read":  true,
		"EON-123456:production:write": true,
		"EON-123456:production:admin": false,
	},
	"admin": {
		"EON-123456:production:read":  true,
		"EON-123456:production:write": true,
		"EON-123456:production:admin": true,
	},
}

func handleEntitlement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EntitlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Entitlement check: UserID=%s, EonID=%s, Env=%s, Action=%s",
		req.UserID, req.EonID, req.Env, req.Action)

	// Check if user is authorized
	entitlementKey := fmt.Sprintf("%s:%s:%s", req.EonID, req.Env, req.Action)
	userPerms, userExists := authorizedUsers[req.UserID]
	entitled := userExists && userPerms[entitlementKey]

	response := EntitlementResponse{
		Entitled: entitled,
	}

	if entitled {
		response.Message = "Access granted"
		log.Printf("Access granted for user %s", req.UserID)
	} else {
		response.Message = "Access denied"
		log.Printf("Access denied for user %s", req.UserID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "entserver-activedirectory-mock",
	})
}

func main() {
	http.HandleFunc("/entitlement", handleEntitlement)
	http.HandleFunc("/health", handleHealth)

	fmt.Println("Mock entserver-activedirectory starting on :8081")
	fmt.Println("Available users and permissions:")
	for user, perms := range authorizedUsers {
		fmt.Printf("  %s:\n", user)
		for perm, allowed := range perms {
			fmt.Printf("    %s: %t\n", perm, allowed)
		}
	}

	log.Fatal(http.ListenAndServe(":8081", nil))
}
