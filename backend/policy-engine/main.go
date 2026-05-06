package main

import (
	"log"
	"net/http"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/server"
)

func main() {
	cfg := config.Load("policy-engine", "8097", "9097")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))
	mux.HandleFunc("/policy/demo", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, map[string]any{
			"mode": "production-safe",
			"protected_scopes": []string{
				"Domain Admins",
				"Enterprise Admins",
				"KRBTGT",
				"Certificate Authorities",
			},
			"approval_thresholds": map[string]string{
				"disable-account": "high",
				"revert-attribute": "high",
				"contain-host": "critical-confirmed",
			},
			"exclusions": []string{
				"break-glass-admin",
				"approved-backup-svc",
			},
		})
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}
