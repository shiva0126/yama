package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/catalog"
	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"
	"ad-assessment/defense-shared/server"
)

func main() {
	cfg := config.Load("defense-api", "8098", "9098")
	cat, err := catalog.LoadDefault()
	if err != nil {
		log.Fatalf("load detector catalog: %v", err)
	}
	pool, err := storage.Open(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("open db pool: %v", err)
	}
	defer pool.Close()

	if err := store.SeedCatalog(context.Background(), pool, cat); err != nil {
		log.Printf("catalog seed skipped: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))
	mux.HandleFunc("/catalog", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, cat)
	})
	mux.HandleFunc("/catalog/summary", func(w http.ResponseWriter, _ *http.Request) {
		if summary, err := store.LoadDefenseSummary(context.Background(), pool); err == nil {
			server.WriteJSON(w, http.StatusOK, map[string]any{
				"version":            cat.Version,
				"family_count":       summary["family_count"],
				"detector_count":     summary["detector_count"],
				"critical_count":     summary["critical_count"],
				"high_count":         summary["high_count"],
				"demo_ready_count":   summary["demo_ready_count"],
				"by_family":          summary["by_family"],
				"response_profiles":  summary["response_profiles"],
			})
			return
		}
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
