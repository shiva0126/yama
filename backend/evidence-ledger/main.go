package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/server"
)

func main() {
	cfg := config.Load("evidence-ledger", "8096", "9096")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))
	mux.HandleFunc("/evidence/bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}

		var bundle events.EvidenceBundle
		if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		server.WriteJSON(w, http.StatusOK, finalizeBundle(bundle))
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

func finalizeBundle(bundle events.EvidenceBundle) events.EvidenceBundle {
	if bundle.ID == "" {
		bundle.ID = "evidence-demo-001"
	}
	if bundle.StorageKey == "" {
		bundle.StorageKey = "demo/" + time.Now().UTC().Format("20060102T150405Z") + ".json"
	}
	if bundle.ContentType == "" {
		bundle.ContentType = "application/json"
	}

	raw, _ := json.Marshal(bundle.Metadata)
	sum := sha256.Sum256(raw)
	bundle.SHA256 = hex.EncodeToString(sum[:])

	return bundle
}
