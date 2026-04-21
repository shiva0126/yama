package orchestrator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ad-assessment/shared/config"
	"ad-assessment/shared/types"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type Orchestrator struct {
	db     *pgxpool.Pool
	rdb    *redis.Client
	cfg    *config.Config
	logger *zap.Logger
	client *http.Client
}

func New(db *pgxpool.Pool, rdb *redis.Client, cfg *config.Config, logger *zap.Logger) *Orchestrator {
	return &Orchestrator{
		db:     db,
		rdb:    rdb,
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

// ============================================================
// Agent Management
// ============================================================

func (o *Orchestrator) RegisterAgent(c *gin.Context) {
	var req struct {
		Name         string   `json:"name" binding:"required"`
		Hostname     string   `json:"hostname" binding:"required"`
		Domain       string   `json:"domain" binding:"required"`
		IPAddress    string   `json:"ip_address"`
		Version      string   `json:"version"`
		Capabilities []string `json:"capabilities"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	apiKey := generateAPIKey()
	id := uuid.New().String()

	_, err := o.db.Exec(context.Background(),
		`INSERT INTO agents (id, name, hostname, domain, ip_address, api_key, status, last_seen, version, capabilities)
		 VALUES ($1, $2, $3, $4, $5, $6, 'online', NOW(), $7, $8)`,
		id, req.Name, req.Hostname, req.Domain, req.IPAddress, apiKey, req.Version, req.Capabilities,
	)
	if err != nil {
		o.logger.Error("failed to register agent", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register agent"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"api_key": apiKey,
		"message": "Agent registered. Store the api_key securely.",
	})
}

func (o *Orchestrator) ListAgents(c *gin.Context) {
	rows, err := o.db.Query(context.Background(),
		`SELECT id, name, hostname, domain, ip_address, status, last_seen, version FROM agents ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var agents []types.CollectorAgent
	for rows.Next() {
		var a types.CollectorAgent
		rows.Scan(&a.ID, &a.Name, &a.Hostname, &a.Domain, &a.IPAddress, &a.Status, &a.LastSeen, &a.Version)
		agents = append(agents, a)
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents, "total": len(agents)})
}

func (o *Orchestrator) GetAgent(c *gin.Context) {
	id := c.Param("id")
	var a types.CollectorAgent
	err := o.db.QueryRow(context.Background(),
		`SELECT id, name, hostname, domain, ip_address, status, last_seen, version FROM agents WHERE id=$1`, id,
	).Scan(&a.ID, &a.Name, &a.Hostname, &a.Domain, &a.IPAddress, &a.Status, &a.LastSeen, &a.Version)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

func (o *Orchestrator) DeleteAgent(c *gin.Context) {
	id := c.Param("id")
	o.db.Exec(context.Background(), `DELETE FROM agents WHERE id=$1`, id)
	c.JSON(http.StatusOK, gin.H{"message": "agent deleted"})
}

func (o *Orchestrator) GetAgentStatus(c *gin.Context) {
	id := c.Param("id")
	var status string
	var lastSeen time.Time
	o.db.QueryRow(context.Background(),
		`SELECT status, last_seen FROM agents WHERE id=$1`, id,
	).Scan(&status, &lastSeen)
	c.JSON(http.StatusOK, gin.H{"status": status, "last_seen": lastSeen})
}

// ============================================================
// Scan Management
// ============================================================

func (o *Orchestrator) CreateScan(c *gin.Context) {
	var req types.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify agent exists and is online
	var agentAPIKey, agentHostname string
	err := o.db.QueryRow(context.Background(),
		`SELECT api_key, hostname FROM agents WHERE id=$1 AND status='online'`, req.AgentID,
	).Scan(&agentAPIKey, &agentHostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent not found or offline"})
		return
	}

	// Create scan record
	scanID := uuid.New().String()
	_, err = o.db.Exec(context.Background(),
		`INSERT INTO scans (id, agent_id, domain, status, progress) VALUES ($1, $2, $3, 'pending', 0)`,
		scanID, req.AgentID, req.Domain,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan"})
		return
	}

	// Determine tasks to run
	taskTypes := req.TaskTypes
	if len(taskTypes) == 0 {
		taskTypes = types.AllTaskTypes
	}

	// Create task records
	for _, tt := range taskTypes {
		taskID := uuid.New().String()
		o.db.Exec(context.Background(),
			`INSERT INTO scan_tasks (id, scan_id, task_type, status) VALUES ($1, $2, $3, 'pending')`,
			taskID, scanID, string(tt),
		)
	}

	// Start scan asynchronously
	go o.executeScan(scanID, req.AgentID, agentAPIKey, req.Domain, taskTypes)

	scan := types.ScanJob{
		ID:        scanID,
		AgentID:   req.AgentID,
		Domain:    req.Domain,
		Status:    types.ScanStatusPending,
		Progress:  0,
		CreatedAt: time.Now(),
	}
	c.JSON(http.StatusCreated, scan)
}

func (o *Orchestrator) executeScan(scanID, agentID, agentAPIKey, domain string, tasks []types.TaskType) {
	ctx := context.Background()

	// Mark scan as running
	o.db.Exec(ctx, `UPDATE scans SET status='running', started_at=NOW() WHERE id=$1`, scanID)
	o.publishProgress(scanID, 5, "Starting collection...")

	// Get agent URL from DB
	var agentURL string
	o.db.QueryRow(ctx, `SELECT ip_address FROM agents WHERE id=$1`, agentID).Scan(&agentURL)
	if agentURL == "" {
		o.db.Exec(ctx, `UPDATE scans SET status='failed', error='agent URL not found' WHERE id=$1`, scanID)
		return
	}
	// Construct agent base URL (agent runs on port 9090)
	collectorBaseURL := fmt.Sprintf("http://%s:9090", agentURL)

	// Create snapshot
	snapshotID := uuid.New().String()
	o.db.Exec(ctx,
		`INSERT INTO inventory_snapshots (id, scan_id, domain) VALUES ($1, $2, $3)`,
		snapshotID, scanID, domain,
	)
	o.db.Exec(ctx, `UPDATE scans SET snapshot_id=$1 WHERE id=$2`, snapshotID, scanID)

	totalTasks := len(tasks)
	completed := 0

	for _, taskType := range tasks {
		o.logger.Info("executing task", zap.String("scan_id", scanID), zap.String("task", string(taskType)))

		// Mark task running
		o.db.Exec(ctx,
			`UPDATE scan_tasks SET status='running', started_at=NOW() WHERE scan_id=$1 AND task_type=$2`,
			scanID, string(taskType),
		)

		result, err := o.callCollector(collectorBaseURL, agentAPIKey, string(taskType), domain)
		if err != nil {
			o.logger.Error("collector task failed", zap.String("task", string(taskType)), zap.Error(err))
			o.db.Exec(ctx,
				`UPDATE scan_tasks SET status='failed', error=$1, completed_at=NOW() WHERE scan_id=$2 AND task_type=$3`,
				err.Error(), scanID, string(taskType),
			)
			continue
		}

		// Store result in inventory service
		itemCount := o.storeInventoryData(ctx, snapshotID, scanID, string(taskType), result)

		o.db.Exec(ctx,
			`UPDATE scan_tasks SET status='completed', items_found=$1, completed_at=NOW() WHERE scan_id=$2 AND task_type=$3`,
			itemCount, scanID, string(taskType),
		)

		completed++
		progress := 10 + (completed*80/totalTasks)
		o.publishProgress(scanID, progress, fmt.Sprintf("Completed: %s (%d/%d)", taskType, completed, totalTasks))
	}

	o.publishProgress(scanID, 90, "Running security analysis...")

	// Trigger analysis engine
	if err := o.triggerAnalysis(ctx, scanID, snapshotID); err != nil {
		o.logger.Error("analysis failed", zap.Error(err))
	}

	o.db.Exec(ctx, `UPDATE scans SET status='completed', completed_at=NOW(), progress=100 WHERE id=$1`, scanID)
	o.publishProgress(scanID, 100, "Scan complete")
}

func (o *Orchestrator) callCollector(baseURL, apiKey, taskType, domain string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/collect/%s", baseURL, taskType)
	payload, _ := json.Marshal(map[string]string{"domain": domain})

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("collector unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("collector returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid collector response: %w", err)
	}
	return result, nil
}

func (o *Orchestrator) storeInventoryData(ctx context.Context, snapshotID, scanID, taskType string, data map[string]interface{}) int {
	// Forward to inventory service
	payload, _ := json.Marshal(map[string]interface{}{
		"snapshot_id": snapshotID,
		"scan_id":     scanID,
		"task_type":   taskType,
		"data":        data,
	})

	req, _ := http.NewRequest(http.MethodPost, o.cfg.InventoryServiceURL+"/internal/store", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		o.logger.Error("inventory store failed", zap.Error(err))
		return 0
	}
	defer resp.Body.Close()

	var result struct {
		Count int `json:"count"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Count
}

func (o *Orchestrator) triggerAnalysis(ctx context.Context, scanID, snapshotID string) error {
	payload, _ := json.Marshal(map[string]string{
		"scan_id":     scanID,
		"snapshot_id": snapshotID,
	})
	req, _ := http.NewRequest(http.MethodPost, o.cfg.AnalysisEngineURL+"/analyze", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (o *Orchestrator) publishProgress(scanID string, progress int, message string) {
	payload, _ := json.Marshal(map[string]interface{}{
		"scan_id":  scanID,
		"progress": progress,
		"message":  message,
	})
	o.rdb.Publish(context.Background(), types.RedisScanProgressChannel, string(payload))
	o.db.Exec(context.Background(), `UPDATE scans SET progress=$1 WHERE id=$2`, progress, scanID)
}

func (o *Orchestrator) ListScans(c *gin.Context) {
	rows, err := o.db.Query(context.Background(),
		`SELECT id, agent_id, domain, status, progress, overall_score, critical_count, high_count,
		        medium_count, low_count, total_findings, created_at, started_at, completed_at
		 FROM scans ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var (
			id, agentID, domain, status string
			progress, score             int
			critical, high, medium, low, total int
			createdAt                   time.Time
			startedAt, completedAt      *time.Time
		)
		rows.Scan(&id, &agentID, &domain, &status, &progress, &score,
			&critical, &high, &medium, &low, &total,
			&createdAt, &startedAt, &completedAt)

		scans = append(scans, map[string]interface{}{
			"id": id, "agent_id": agentID, "domain": domain,
			"status": status, "progress": progress, "overall_score": score,
			"critical_count": critical, "high_count": high, "medium_count": medium,
			"low_count": low, "total_findings": total,
			"created_at": createdAt, "started_at": startedAt, "completed_at": completedAt,
		})
	}
	if scans == nil {
		scans = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{"scans": scans, "total": len(scans)})
}

func (o *Orchestrator) GetScan(c *gin.Context) {
	id := c.Param("id")
	var scan map[string]interface{}

	var (
		scanID, agentID, domain, status string
		progress, score                  int
		critical, high, medium, low, total int
		snapshotID                        *string
		createdAt                         time.Time
		startedAt, completedAt            *time.Time
	)
	err := o.db.QueryRow(context.Background(),
		`SELECT id, agent_id, domain, status, progress, overall_score, critical_count, high_count,
		        medium_count, low_count, total_findings, snapshot_id, created_at, started_at, completed_at
		 FROM scans WHERE id=$1`, id,
	).Scan(&scanID, &agentID, &domain, &status, &progress, &score,
		&critical, &high, &medium, &low, &total, &snapshotID,
		&createdAt, &startedAt, &completedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}

	scan = map[string]interface{}{
		"id": scanID, "agent_id": agentID, "domain": domain,
		"status": status, "progress": progress, "overall_score": score,
		"critical_count": critical, "high_count": high, "medium_count": medium,
		"low_count": low, "total_findings": total, "snapshot_id": snapshotID,
		"created_at": createdAt, "started_at": startedAt, "completed_at": completedAt,
	}

	// Get tasks
	rows, _ := o.db.Query(context.Background(),
		`SELECT id, task_type, status, items_found, error, started_at, completed_at FROM scan_tasks WHERE scan_id=$1`, id)
	defer rows.Close()
	var tasks []map[string]interface{}
	for rows.Next() {
		var taskID, taskType, taskStatus string
		var itemsFound int
		var taskError *string
		var taskStarted, taskCompleted *time.Time
		rows.Scan(&taskID, &taskType, &taskStatus, &itemsFound, &taskError, &taskStarted, &taskCompleted)
		tasks = append(tasks, map[string]interface{}{
			"id": taskID, "type": taskType, "status": taskStatus,
			"items_found": itemsFound, "error": taskError,
			"started_at": taskStarted, "completed_at": taskCompleted,
		})
	}
	scan["tasks"] = tasks

	c.JSON(http.StatusOK, scan)
}

func (o *Orchestrator) CancelScan(c *gin.Context) {
	id := c.Param("id")
	o.db.Exec(context.Background(), `UPDATE scans SET status='cancelled' WHERE id=$1 AND status IN ('pending','running')`, id)
	c.JSON(http.StatusOK, gin.H{"message": "scan cancelled"})
}

func (o *Orchestrator) GetProgress(c *gin.Context) {
	id := c.Param("id")
	var progress int
	var status string
	o.db.QueryRow(context.Background(), `SELECT progress, status FROM scans WHERE id=$1`, id).Scan(&progress, &status)
	c.JSON(http.StatusOK, gin.H{"scan_id": id, "progress": progress, "status": status})
}

func (o *Orchestrator) GetScoreCard(c *gin.Context) {
	id := c.Param("id")
	var score, critical, high, medium, low, info, total int
	o.db.QueryRow(context.Background(),
		`SELECT COALESCE(overall_score,0), COALESCE(critical_count,0), COALESCE(high_count,0),
		        COALESCE(medium_count,0), COALESCE(low_count,0), COALESCE(info_count,0), COALESCE(total_findings,0)
		 FROM scans WHERE id=$1`, id,
	).Scan(&score, &critical, &high, &medium, &low, &info, &total)
	c.JSON(http.StatusOK, types.ScoreCard{
		OverallScore:  score,
		CriticalCount: critical,
		HighCount:     high,
		MediumCount:   medium,
		LowCount:      low,
		InfoCount:     info,
		TotalFindings: total,
	})
}

func (o *Orchestrator) HandleTaskResult(c *gin.Context) {
	// Called by collector agent to push results directly
	c.JSON(http.StatusOK, gin.H{"message": "received"})
}

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
