package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ad-assessment/shared/config"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	cfg := config.Load()

	pool, err := pgxpool.New(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("db connection failed: %v", err)
	}
	defer pool.Close()

	pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS snapshot_metadata (
			snapshot_id UUID REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
			key         VARCHAR(50) NOT NULL,
			value       JSONB,
			PRIMARY KEY (snapshot_id, key)
		)`)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "inventory-service"})
	})

	// Internal: called by scan-orchestrator to store collected data
	r.POST("/internal/store", func(c *gin.Context) {
		var payload struct {
			SnapshotID string                 `json:"snapshot_id"`
			ScanID     string                 `json:"scan_id"`
			TaskType   string                 `json:"task_type"`
			Data       map[string]interface{} `json:"data"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		count := storeTaskData(pool, payload.SnapshotID, payload.ScanID, payload.TaskType, payload.Data, logger)
		c.JSON(http.StatusOK, gin.H{"count": count})
	})

	// Snapshot endpoints
	r.GET("/snapshots", func(c *gin.Context) {
		rows, err := pool.Query(context.Background(),
			`SELECT id, scan_id, domain, taken_at FROM inventory_snapshots ORDER BY taken_at DESC LIMIT 50`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var snapshots []map[string]interface{}
		for rows.Next() {
			var id, scanID, domain string
			var takenAt time.Time
			rows.Scan(&id, &scanID, &domain, &takenAt)
			snapshots = append(snapshots, map[string]interface{}{
				"id": id, "scan_id": scanID, "domain": domain, "taken_at": takenAt,
			})
		}
		if snapshots == nil {
			snapshots = []map[string]interface{}{}
		}
		c.JSON(http.StatusOK, gin.H{"snapshots": snapshots, "total": len(snapshots)})
	})

	r.GET("/snapshots/:id/full", func(c *gin.Context) {
		id := c.Param("id")
		snapshot := buildFullSnapshot(pool, id, logger)
		c.JSON(http.StatusOK, snapshot)
	})

	r.GET("/snapshots/:id/users", func(c *gin.Context) {
		queryInventory(c, pool, "ad_users", c.Param("id"))
	})
	r.GET("/snapshots/:id/groups", func(c *gin.Context) {
		queryInventory(c, pool, "ad_groups", c.Param("id"))
	})
	r.GET("/snapshots/:id/computers", func(c *gin.Context) {
		queryInventory(c, pool, "ad_computers", c.Param("id"))
	})
	r.GET("/snapshots/:id/gpos", func(c *gin.Context) {
		queryInventory(c, pool, "ad_gpos", c.Param("id"))
	})
	r.GET("/snapshots/:id/dcs", func(c *gin.Context) {
		queryInventory(c, pool, "ad_domain_controllers", c.Param("id"))
	})

	// Topology endpoint — returns a rich view for graph visualization
	r.GET("/snapshots/:id/topology", func(c *gin.Context) {
		buildTopologyResponse(c, pool, c.Param("id"), logger)
	})

	// ADCS
	r.GET("/snapshots/:id/cert-templates", func(c *gin.Context) {
		querySnapshotMeta(c, pool, "cert_templates", c.Param("id"))
	})
	r.GET("/snapshots/:id/cert-authorities", func(c *gin.Context) {
		querySnapshotMeta(c, pool, "cert_authorities", c.Param("id"))
	})

	srv := &http.Server{Addr: ":" + cfg.Port, Handler: r}
	go func() {
		logger.Info("Inventory Service started", zap.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func storeTaskData(pool *pgxpool.Pool, snapshotID, scanID, taskType string, data map[string]interface{}, logger *zap.Logger) int {
	ctx := context.Background()
	count := 0

	switch taskType {
	case "users":
		if users, ok := data["users"].([]interface{}); ok {
			for _, u := range users {
				userData, _ := json.Marshal(u)
				uMap, _ := u.(map[string]interface{})
				_, err := pool.Exec(ctx,
					`INSERT INTO ad_users (snapshot_id, scan_id, sam_account_name, distinguished_name, domain, data,
					  is_privileged, is_kerberoastable, is_asrep_roastable, has_spn, enabled)
					 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
					snapshotID, scanID,
					strVal(uMap, "sam_account_name"),
					strVal(uMap, "distinguished_name"),
					strVal(uMap, "domain"),
					userData,
					boolVal(uMap, "is_privileged"),
					len(getSlice(uMap, "service_principal_names")) > 0,
					boolVal(uMap, "dont_require_preauth"),
					len(getSlice(uMap, "service_principal_names")) > 0,
					boolVal(uMap, "enabled"),
				)
				if err == nil {
					count++
				}
			}
		}
	case "groups":
		if groups, ok := data["groups"].([]interface{}); ok {
			for _, g := range groups {
				gData, _ := json.Marshal(g)
				gMap, _ := g.(map[string]interface{})
				members := getSlice(gMap, "members")
				pool.Exec(ctx,
					`INSERT INTO ad_groups (snapshot_id, scan_id, name, distinguished_name, domain, is_privileged, member_count, data)
					 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
					snapshotID, scanID,
					strVal(gMap, "name"), strVal(gMap, "distinguished_name"),
					strVal(gMap, "domain"), boolVal(gMap, "is_privileged"),
					len(members), gData,
				)
				count++
			}
		}
	case "computers":
		if computers, ok := data["computers"].([]interface{}); ok {
			for _, comp := range computers {
				cData, _ := json.Marshal(comp)
				cMap, _ := comp.(map[string]interface{})
				pool.Exec(ctx,
					`INSERT INTO ad_computers (snapshot_id, scan_id, name, distinguished_name, domain, os,
					  is_dc, enabled, laps_enabled, unconstrained_delegation, data)
					 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
					snapshotID, scanID,
					strVal(cMap, "name"), strVal(cMap, "distinguished_name"),
					strVal(cMap, "domain"), strVal(cMap, "operating_system"),
					boolVal(cMap, "is_domain_controller"), boolVal(cMap, "enabled"),
					boolVal(cMap, "laps_enabled"), boolVal(cMap, "trusted_for_delegation"),
					cData,
				)
				count++
			}
		}
	case "gpos":
		if gpos, ok := data["gpos"].([]interface{}); ok {
			for _, g := range gpos {
				gData, _ := json.Marshal(g)
				gMap, _ := g.(map[string]interface{})
				pool.Exec(ctx,
					`INSERT INTO ad_gpos (snapshot_id, scan_id, name, guid, domain, is_linked, data)
					 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
					snapshotID, scanID,
					strVal(gMap, "display_name"), strVal(gMap, "id"),
					strVal(gMap, "domain"), boolVal(gMap, "is_linked"),
					gData,
				)
				count++
			}
		}
	case "dcinfo":
		if dcs, ok := data["domain_controllers"].([]interface{}); ok {
			for _, dc := range dcs {
				dcData, _ := json.Marshal(dc)
				dcMap, _ := dc.(map[string]interface{})
				pool.Exec(ctx,
					`INSERT INTO ad_domain_controllers (snapshot_id, scan_id, name, domain, os, is_read_only, data)
					 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
					snapshotID, scanID,
					strVal(dcMap, "name"), strVal(dcMap, "domain"),
					strVal(dcMap, "operating_system"), boolVal(dcMap, "is_read_only"),
					dcData,
				)
				count++
			}
		}

	case "adcs":
		// Store the full ADCS payload as snapshot metadata
		adcsJSON, _ := json.Marshal(data)
		pool.Exec(ctx,
			`INSERT INTO snapshot_metadata (snapshot_id, key, value)
			 VALUES ($1, 'adcs', $2)
			 ON CONFLICT (snapshot_id, key) DO UPDATE SET value = EXCLUDED.value`,
			snapshotID, adcsJSON,
		)
		if templates, ok := data["cert_templates"].([]interface{}); ok {
			count += len(templates)
		}

	case "sites":
		// Store sites payload as snapshot metadata
		sitesJSON, _ := json.Marshal(data)
		pool.Exec(ctx,
			`INSERT INTO snapshot_metadata (snapshot_id, key, value)
			 VALUES ($1, 'sites', $2)
			 ON CONFLICT (snapshot_id, key) DO UPDATE SET value = EXCLUDED.value`,
			snapshotID, sitesJSON,
		)
		if sites, ok := data["sites"].([]interface{}); ok {
			count += len(sites)
		}

		// Also persist machine_account_quota and recycle_bin on the snapshot
		maq := intVal(data, "machine_account_quota")
		rb := boolVal(data, "recycle_bin_enabled")
		maqJSON, _ := json.Marshal(map[string]interface{}{
			"machine_account_quota": maq,
			"recycle_bin_enabled":   rb,
		})
		pool.Exec(ctx,
			`INSERT INTO snapshot_metadata (snapshot_id, key, value)
			 VALUES ($1, 'domain_config', $2)
			 ON CONFLICT (snapshot_id, key) DO UPDATE SET value = EXCLUDED.value`,
			snapshotID, maqJSON,
		)
	}

	return count
}

func buildFullSnapshot(pool *pgxpool.Pool, snapshotID string, logger *zap.Logger) map[string]interface{} {
	ctx := context.Background()
	snapshot := map[string]interface{}{
		"id":                 snapshotID,
		"users":              []interface{}{},
		"groups":             []interface{}{},
		"computers":          []interface{}{},
		"gpos":               []interface{}{},
		"domain_controllers": []interface{}{},
		"trusts":             []interface{}{},
		"acls":               []interface{}{},
		"cert_templates":     []interface{}{},
		"cert_authorities":   []interface{}{},
		"machine_account_quota": 0,
		"recycle_bin_enabled":   false,
	}

	for _, table := range []string{"ad_users", "ad_groups", "ad_computers", "ad_gpos", "ad_domain_controllers"} {
		rows, err := pool.Query(ctx, `SELECT data FROM `+table+` WHERE snapshot_id=$1`, snapshotID)
		if err != nil {
			logger.Error("failed to load "+table, zap.Error(err))
			continue
		}
		var items []interface{}
		for rows.Next() {
			var dataJSON []byte
			rows.Scan(&dataJSON)
			var item interface{}
			json.Unmarshal(dataJSON, &item)
			items = append(items, item)
		}
		rows.Close()
		if items != nil {
			snapshot[tableToKey(table)] = items
		}
	}

	// Load ADCS metadata
	var adcsData map[string]interface{}
	loadMeta(ctx, pool, snapshotID, "adcs", &adcsData)
	if adcsData != nil {
		if v, ok := adcsData["cert_templates"]; ok {
			snapshot["cert_templates"] = v
		}
		if v, ok := adcsData["cert_authorities"]; ok {
			snapshot["cert_authorities"] = v
		}
	}

	// Load domain config (machine quota, recycle bin)
	var domainCfg map[string]interface{}
	loadMeta(ctx, pool, snapshotID, "domain_config", &domainCfg)
	if domainCfg != nil {
		snapshot["machine_account_quota"] = extractIntKey(domainCfg, "machine_account_quota")
		snapshot["recycle_bin_enabled"] = extractBoolKey(domainCfg, "recycle_bin_enabled")
	}

	return snapshot
}

func queryInventory(c *gin.Context, pool *pgxpool.Pool, table, snapshotID string) {
	rows, err := pool.Query(context.Background(),
		`SELECT data FROM `+table+` WHERE snapshot_id=$1`, snapshotID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var items []interface{}
	for rows.Next() {
		var dataJSON []byte
		rows.Scan(&dataJSON)
		var item interface{}
		json.Unmarshal(dataJSON, &item)
		items = append(items, item)
	}
	if items == nil {
		items = []interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

// buildTopologyResponse assembles a rich topology payload for the frontend graph.
func buildTopologyResponse(c *gin.Context, pool *pgxpool.Pool, snapshotID string, logger *zap.Logger) {
	ctx := context.Background()

	// DCs
	dcRows, _ := pool.Query(ctx, `SELECT data FROM ad_domain_controllers WHERE snapshot_id=$1`, snapshotID)
	var dcs []interface{}
	for dcRows.Next() {
		var d []byte
		dcRows.Scan(&d)
		var v interface{}
		json.Unmarshal(d, &v)
		dcs = append(dcs, v)
	}
	dcRows.Close()

	// Trusts (stored in topology metadata or domain info)
	var sitesData, adcsData, domainCfg map[string]interface{}
	loadMeta(ctx, pool, snapshotID, "sites", &sitesData)
	loadMeta(ctx, pool, snapshotID, "adcs", &adcsData)
	loadMeta(ctx, pool, snapshotID, "domain_config", &domainCfg)

	// Snapshot base info
	var domain string
	var takenAt time.Time
	pool.QueryRow(ctx, `SELECT domain, taken_at FROM inventory_snapshots WHERE id=$1`, snapshotID).Scan(&domain, &takenAt)

	// Domain controllers count
	var dcCount, userCount, computerCount, groupCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM ad_domain_controllers WHERE snapshot_id=$1`, snapshotID).Scan(&dcCount)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM ad_users WHERE snapshot_id=$1`, snapshotID).Scan(&userCount)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM ad_computers WHERE snapshot_id=$1`, snapshotID).Scan(&computerCount)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM ad_groups WHERE snapshot_id=$1`, snapshotID).Scan(&groupCount)

	topo := map[string]interface{}{
		"snapshot_id": snapshotID,
		"domain":      domain,
		"taken_at":    takenAt,
		"summary": map[string]interface{}{
			"dc_count":       dcCount,
			"user_count":     userCount,
			"computer_count": computerCount,
			"group_count":    groupCount,
		},
		"domain_controllers": nilSlice(dcs),
		"sites":              extractKey(sitesData, "sites"),
		"site_links":         extractKey(sitesData, "site_links"),
		"cert_templates":     extractKey(adcsData, "cert_templates"),
		"cert_authorities":   extractKey(adcsData, "cert_authorities"),
		"machine_account_quota": extractIntKey(domainCfg, "machine_account_quota"),
		"recycle_bin_enabled":   extractBoolKey(domainCfg, "recycle_bin_enabled"),
	}
	c.JSON(200, topo)
}

// querySnapshotMeta reads a key from snapshot_metadata and returns parsed JSON.
func querySnapshotMeta(c *gin.Context, pool *pgxpool.Pool, key, snapshotID string) {
	ctx := context.Background()
	var raw []byte
	err := pool.QueryRow(ctx,
		`SELECT value FROM snapshot_metadata WHERE snapshot_id=$1 AND key=$2`, snapshotID, key,
	).Scan(&raw)
	if err != nil {
		c.JSON(200, gin.H{"items": []interface{}{}, "total": 0})
		return
	}
	var data map[string]interface{}
	json.Unmarshal(raw, &data)
	items, _ := data[key].([]interface{})
	if items == nil {
		items = []interface{}{}
	}
	c.JSON(200, gin.H{"items": items, "total": len(items)})
}

func loadMeta(ctx context.Context, pool *pgxpool.Pool, snapshotID, key string, out *map[string]interface{}) {
	var raw []byte
	pool.QueryRow(ctx, `SELECT value FROM snapshot_metadata WHERE snapshot_id=$1 AND key=$2`, snapshotID, key).Scan(&raw)
	if raw != nil {
		json.Unmarshal(raw, out)
	}
}

func extractKey(m map[string]interface{}, key string) interface{} {
	if m == nil {
		return []interface{}{}
	}
	if v, ok := m[key]; ok {
		return v
	}
	return []interface{}{}
}

func extractIntKey(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

func extractBoolKey(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func nilSlice(s []interface{}) []interface{} {
	if s == nil {
		return []interface{}{}
	}
	return s
}

func intVal(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

func tableToKey(table string) string {
	m := map[string]string{
		"ad_users":              "users",
		"ad_groups":             "groups",
		"ad_computers":          "computers",
		"ad_gpos":               "gpos",
		"ad_domain_controllers": "domain_controllers",
	}
	if k, ok := m[table]; ok {
		return k
	}
	return table
}

func strVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolVal(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok && v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getSlice(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.([]interface{}); ok {
			return s
		}
	}
	return nil
}
