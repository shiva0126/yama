package server

import (
	"encoding/json"
	"net/http"
)

// HealthHandler is shared by the early defense-plane service scaffolds so each
// service exposes a consistent probe even before gRPC contracts are generated.
func HealthHandler(serviceName string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": serviceName,
			"status":  "ok",
		})
	}
}

// WriteJSON keeps the demo services consistent and avoids repeating response
// boilerplate in every small handler.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
