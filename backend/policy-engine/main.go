package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Exclusion struct {
	ID         string     `json:"id"`
	ScopeType  string     `json:"scope_type"`
	ScopeValue string     `json:"scope_value"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
}

var defaultApprovalThresholds = map[string]string{
	"disable-account":  "high",
	"revert-attribute": "high",
	"contain-host":     "critical-confirmed",
	"collect-evidence": "automatic",
}

var defaultProtectedScopes = []string{
	"Domain Admins", "Enterprise Admins", "KRBTGT", "Certificate Authorities",
}

// severityRank maps severity strings to comparable integers.
var severityRank = map[string]int{
	"low": 1, "medium": 2, "high": 3, "critical": 4, "critical-confirmed": 5,
}

func main() {
	cfg := config.Load("policy-engine", "8097", "9097")
	pool, err := storage.Open(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("open db pool: %v", err)
	}
	defer pool.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))

	// GET /policy — full active policy with live exclusions
	mux.HandleFunc("/policy", func(w http.ResponseWriter, r *http.Request) {
		exclusions := queryExclusions(r.Context(), pool)
		server.WriteJSON(w, http.StatusOK, map[string]any{
			"mode":                "production-safe",
			"protected_scopes":    defaultProtectedScopes,
			"approval_thresholds": defaultApprovalThresholds,
			"exclusions":          exclusions,
		})
	})

	// GET /policy/exclusion — list exclusions
	// POST /policy/exclusion — add exclusion
	mux.HandleFunc("/policy/exclusion", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			exclusions := queryExclusions(r.Context(), pool)
			server.WriteJSON(w, http.StatusOK, map[string]any{"exclusions": exclusions, "total": len(exclusions)})

		case http.MethodPost:
			var req struct {
				ScopeType  string  `json:"scope_type"`
				ScopeValue string  `json:"scope_value"`
				Reason     string  `json:"reason"`
				ExpiresAt  *string `json:"expires_at,omitempty"`
				CreatedBy  string  `json:"created_by"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if req.ScopeType == "" || req.ScopeValue == "" {
				server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "scope_type and scope_value required"})
				return
			}
			var expiresAt *time.Time
			if req.ExpiresAt != nil {
				if t, err := time.Parse(time.RFC3339, *req.ExpiresAt); err == nil {
					expiresAt = &t
				}
			}
			var id string
			err := pool.QueryRow(r.Context(), `
				INSERT INTO defense_exclusions (scope_type, scope_value, reason, expires_at, created_by)
				VALUES ($1, $2, $3, $4, $5) RETURNING id
			`, req.ScopeType, req.ScopeValue, req.Reason, expiresAt, req.CreatedBy).Scan(&id)
			if err != nil {
				log.Printf("create exclusion: %v", err)
				server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
				return
			}
			server.WriteJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "created"})

		default:
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
		}
	})

	// DELETE /policy/exclusion/{id}
	mux.HandleFunc("/policy/exclusion/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "DELETE required"})
			return
		}
		id := r.URL.Path[len("/policy/exclusion/"):]
		if id == "" {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
			return
		}
		if _, err := pool.Exec(r.Context(), `DELETE FROM defense_exclusions WHERE id = $1`, id); err != nil {
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		server.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	// POST /policy/evaluate — check if an action is allowed under current policy
	mux.HandleFunc("/policy/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var req struct {
			ActionType  string `json:"action_type"`
			Severity    string `json:"severity"`
			Confidence  string `json:"confidence"`
			TargetValue string `json:"target_value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// Block if target is excluded
		if checkExclusion(r.Context(), pool, req.TargetValue) {
			server.WriteJSON(w, http.StatusOK, map[string]any{
				"allowed": false,
				"reason":  "target is in the exclusion list",
				"mode":    "blocked",
			})
			return
		}

		// Require approval for protected scopes
		for _, scope := range defaultProtectedScopes {
			if req.TargetValue == scope {
				server.WriteJSON(w, http.StatusOK, map[string]any{
					"allowed": true,
					"reason":  "target is a protected scope — escalated approval required",
					"mode":    "approval-required",
				})
				return
			}
		}

		threshold, ok := defaultApprovalThresholds[req.ActionType]
		if !ok {
			threshold = "approval-required"
		}

		mode := "approval-required"
		if threshold == "automatic" {
			mode = "automatic"
		} else if severityRank[req.Severity] >= severityRank[threshold] ||
			severityRank[req.Confidence] >= severityRank[threshold] {
			mode = "automatic"
		}

		server.WriteJSON(w, http.StatusOK, map[string]any{
			"allowed":   true,
			"mode":      mode,
			"threshold": threshold,
			"severity":  req.Severity,
			"confidence": req.Confidence,
		})
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

func queryExclusions(ctx context.Context, pool *pgxpool.Pool) []Exclusion {
	rows, err := pool.Query(ctx, `
		SELECT id, scope_type, scope_value, COALESCE(reason,''), expires_at,
		       COALESCE(created_by,''), created_at
		FROM   defense_exclusions
		WHERE  expires_at IS NULL OR expires_at > NOW()
		ORDER  BY created_at DESC
	`)
	if err != nil {
		log.Printf("query exclusions: %v", err)
		return []Exclusion{}
	}
	defer rows.Close()

	var out []Exclusion
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.ID, &e.ScopeType, &e.ScopeValue, &e.Reason, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt); err != nil {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		return []Exclusion{}
	}
	return out
}

func checkExclusion(ctx context.Context, pool *pgxpool.Pool, targetValue string) bool {
	var count int
	pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM defense_exclusions
		WHERE  scope_value = $1
		  AND  (expires_at IS NULL OR expires_at > NOW())
	`, targetValue).Scan(&count)
	return count > 0
}
