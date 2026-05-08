package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/catalog"
	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

const agentOfflineThreshold = 3 * time.Minute

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

	// Background worker: mark agents offline when heartbeat is stale
	go runAgentTimeoutWorker(pool)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))

	// ── Catalog ──────────────────────────────────────────────
	mux.HandleFunc("/catalog", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, cat)
	})
	mux.HandleFunc("/catalog/summary", func(w http.ResponseWriter, _ *http.Request) {
		if summary, err := store.LoadDefenseSummary(context.Background(), pool); err == nil {
			server.WriteJSON(w, http.StatusOK, map[string]any{
				"version":           cat.Version,
				"family_count":      summary["family_count"],
				"detector_count":    summary["detector_count"],
				"critical_count":    summary["critical_count"],
				"high_count":        summary["high_count"],
				"demo_ready_count":  summary["demo_ready_count"],
				"by_family":         summary["by_family"],
				"response_profiles": summary["response_profiles"],
			})
			return
		}
		server.WriteJSON(w, http.StatusOK, catalog.BuildCoverageSummary(cat))
	})

	// ── Agent heartbeat ───────────────────────────────────────
	mux.HandleFunc("/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var req struct {
			AgentID    string `json:"agent_id"`
			DefenseURL string `json:"defense_url,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id required"})
			return
		}

		tag, err := pool.Exec(context.Background(), `
			UPDATE agents
			SET    status      = 'online',
			       last_seen   = NOW(),
			       defense_url = COALESCE(NULLIF($2, ''), defense_url),
			       defense_mode = TRUE
			WHERE  id = $1
		`, req.AgentID, req.DefenseURL)
		if err != nil {
			log.Printf("heartbeat update: %v", err)
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		if tag.RowsAffected() == 0 {
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		server.WriteJSON(w, http.StatusOK, map[string]string{
			"status":      "ok",
			"agent_id":    req.AgentID,
			"server_time": time.Now().UTC().Format(time.RFC3339),
		})
	})

	// ── Agents list (defense view) ────────────────────────────
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(context.Background(), `
			SELECT id, name, hostname, domain, status, last_seen, defense_mode, defense_url
			FROM   agents
			ORDER  BY created_at DESC
		`)
		if err != nil {
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		var agents []map[string]any
		for rows.Next() {
			var id, name, hostname, domain, status string
			var lastSeen *time.Time
			var defenseMode bool
			var defenseURL *string
			rows.Scan(&id, &name, &hostname, &domain, &status, &lastSeen, &defenseMode, &defenseURL)
			agents = append(agents, map[string]any{
				"id": id, "name": name, "hostname": hostname, "domain": domain,
				"status": status, "last_seen": lastSeen,
				"defense_mode": defenseMode, "defense_url": defenseURL,
			})
		}
		if agents == nil {
			agents = []map[string]any{}
		}
		server.WriteJSON(w, http.StatusOK, map[string]any{"agents": agents, "total": len(agents)})
	})

	// ── Incidents ─────────────────────────────────────────────
	mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(context.Background(), `
			SELECT id, title, severity, confidence, status, primary_actor, primary_target,
			       domain, opened_at, last_updated_at
			FROM   defense_incidents
			ORDER  BY opened_at DESC
			LIMIT  100
		`)
		if err != nil {
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		var incidents []map[string]any
		for rows.Next() {
			var id, title, severity, confidence, status string
			var actor, target, domain *string
			var openedAt, lastUpdated time.Time
			rows.Scan(&id, &title, &severity, &confidence, &status, &actor, &target, &domain, &openedAt, &lastUpdated)
			incidents = append(incidents, map[string]any{
				"id": id, "title": title, "severity": severity, "confidence": confidence,
				"status": status, "primary_actor": actor, "primary_target": target,
				"domain": domain, "opened_at": openedAt, "last_updated_at": lastUpdated,
			})
		}
		if incidents == nil {
			incidents = []map[string]any{}
		}
		server.WriteJSON(w, http.StatusOK, map[string]any{"incidents": incidents, "total": len(incidents)})
	})

	// ── Detections ────────────────────────────────────────────
	mux.HandleFunc("/detections", func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(context.Background(), `
			SELECT id, detector_id, title, severity, confidence, domain, source_host,
			       actor, target, detected_at
			FROM   defense_detections
			ORDER  BY detected_at DESC
			LIMIT  200
		`)
		if err != nil {
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		var detections []map[string]any
		for rows.Next() {
			var id, detectorID, title, severity, confidence string
			var domain, sourceHost, actor, target *string
			var detectedAt time.Time
			rows.Scan(&id, &detectorID, &title, &severity, &confidence, &domain,
				&sourceHost, &actor, &target, &detectedAt)
			detections = append(detections, map[string]any{
				"id": id, "detector_id": detectorID, "title": title,
				"severity": severity, "confidence": confidence, "domain": domain,
				"source_host": sourceHost, "actor": actor, "target": target,
				"detected_at": detectedAt,
			})
		}
		if detections == nil {
			detections = []map[string]any{}
		}
		server.WriteJSON(w, http.StatusOK, map[string]any{"detections": detections, "total": len(detections)})
	})

	// ── Response actions ──────────────────────────────────────
	mux.HandleFunc("/responses", func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(context.Background(), `
			SELECT id, incident_id, action_type, mode, status, target_type, target_value, created_at
			FROM   defense_response_actions
			ORDER  BY created_at DESC
			LIMIT  100
		`)
		if err != nil {
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		var actions []map[string]any
		for rows.Next() {
			var id, incidentID, actionType, mode, status string
			var targetType, targetValue *string
			var createdAt time.Time
			rows.Scan(&id, &incidentID, &actionType, &mode, &status, &targetType, &targetValue, &createdAt)
			actions = append(actions, map[string]any{
				"id": id, "incident_id": incidentID, "action_type": actionType,
				"mode": mode, "status": status, "target_type": targetType,
				"target_value": targetValue, "created_at": createdAt,
			})
		}
		if actions == nil {
			actions = []map[string]any{}
		}
		server.WriteJSON(w, http.StatusOK, map[string]any{"actions": actions, "total": len(actions)})
	})

	// ── Demo endpoints (used by frontend before real telemetry) ──
	mux.HandleFunc("/incidents/demo", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, catalog.DemoIncidents(time.Now().UTC()))
	})
	mux.HandleFunc("/detections/demo", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, catalog.DemoDetections(time.Now().UTC()))
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

// runAgentTimeoutWorker marks agents offline when their last heartbeat is older than the threshold.
func runAgentTimeoutWorker(pool *pgxpool.Pool) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := pool.Exec(ctx, `
			UPDATE agents
			SET    status = 'offline'
			WHERE  defense_mode = TRUE
			  AND  status = 'online'
			  AND  last_seen < NOW() - ($1 || ' seconds')::interval
		`, int(agentOfflineThreshold.Seconds()))
		if err != nil {
			log.Printf("agent timeout worker: %v", err)
		}
		cancel()
	}
}
