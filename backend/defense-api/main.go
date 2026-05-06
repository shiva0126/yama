package main

import (
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/catalog"
	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/server"
)

func main() {
	cfg := config.Load("defense-api", "8098", "9098")
	cat, err := catalog.LoadDefault()
	if err != nil {
		log.Fatalf("load detector catalog: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))
	mux.HandleFunc("/catalog", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, cat)
	})
	mux.HandleFunc("/catalog/summary", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, catalog.BuildCoverageSummary(cat))
	})
	mux.HandleFunc("/incidents/demo", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, catalog.DemoIncidents(time.Now().UTC()))
	})
	mux.HandleFunc("/detections/demo", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, catalog.DemoDetections(time.Now().UTC()))
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}
