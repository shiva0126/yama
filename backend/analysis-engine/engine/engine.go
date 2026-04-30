package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"ad-assessment/analysis-engine/indicators"
	"ad-assessment/shared/types"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type Engine struct {
	db           *pgxpool.Pool
	rdb          *redis.Client
	inventoryURL string
	logger       *zap.Logger
	client       *http.Client
}

func New(db *pgxpool.Pool, rdb *redis.Client, inventoryURL string, logger *zap.Logger) *Engine {
	return &Engine{
		db:           db,
		rdb:          rdb,
		inventoryURL: inventoryURL,
		logger:       logger,
		client:       &http.Client{Timeout: 120 * time.Second},
	}
}

// Analyze is called after a scan completes collection — fetches inventory and runs all indicators
func (e *Engine) Analyze(c *gin.Context) {
	var req struct {
		ScanID     string `json:"scan_id" binding:"required"`
		SnapshotID string `json:"snapshot_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	go func() {
		if err := e.runAnalysis(req.ScanID, req.SnapshotID); err != nil {
			e.logger.Error("analysis failed", zap.String("scan_id", req.ScanID), zap.Error(err))
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"message": "analysis started", "scan_id": req.ScanID})
}

func (e *Engine) runAnalysis(scanID, snapshotID string) error {
	ctx := context.Background()
	e.logger.Info("starting analysis", zap.String("scan_id", scanID))

	// Fetch full snapshot from inventory service
	snapshot, err := e.fetchSnapshot(snapshotID)
	if err != nil {
		return err
	}

	var allFindings []types.Finding

	// Core indicator categories
	allFindings = append(allFindings, indicators.CheckKerberos(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckAccounts(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckPrivilegedAccess(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckGroupPolicy(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckDomainControllers(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckADStructure(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckDelegation(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckTrusts(snapshot, scanID)...)
	// New: ADCS / PKI and advanced checks
	allFindings = append(allFindings, indicators.CheckPKI(snapshot, scanID)...)
	allFindings = append(allFindings, indicators.CheckAdvanced(snapshot, scanID)...)

	// Persist findings
	for _, f := range allFindings {
		f.ID = uuid.New().String()
		f.DetectedAt = time.Now()
		f.IsNew = true

		affectedJSON, _ := json.Marshal(f.AffectedObjects)
		_, err := e.db.Exec(ctx,
			`INSERT INTO findings (id, scan_id, indicator_id, name, description, severity, category,
			  risk_score, affected_objects, remediation, "references", mitre, is_new, detected_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			f.ID, f.ScanID, f.IndicatorID, f.Name, f.Description,
			string(f.Severity), string(f.Category), f.RiskScore,
			affectedJSON, f.Remediation, f.References, f.MITRE, f.IsNew, f.DetectedAt,
		)
		if err != nil {
			e.logger.Error("failed to store finding", zap.Error(err))
		}

		// Publish new finding event
		payload, _ := json.Marshal(f)
		e.rdb.Publish(ctx, types.RedisNewFindingChannel, string(payload))
	}

	// Compute score and update scan
	scoreCard := computeScoreCard(allFindings)
	_, err = e.db.Exec(ctx,
		`UPDATE scans SET overall_score=$1, critical_count=$2, high_count=$3, medium_count=$4,
		  low_count=$5, info_count=$6, total_findings=$7 WHERE id=$8`,
		scoreCard.OverallScore, scoreCard.CriticalCount, scoreCard.HighCount,
		scoreCard.MediumCount, scoreCard.LowCount, scoreCard.InfoCount,
		scoreCard.TotalFindings, scanID,
	)

	e.logger.Info("analysis complete",
		zap.String("scan_id", scanID),
		zap.Int("findings", len(allFindings)),
		zap.Int("score", scoreCard.OverallScore),
	)
	return err
}

func (e *Engine) fetchSnapshot(snapshotID string) (*types.InventorySnapshot, error) {
	resp, err := e.client.Get(e.inventoryURL + "/snapshots/" + snapshotID + "/full")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var snapshot types.InventorySnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func computeScoreCard(findings []types.Finding) types.ScoreCard {
	card := types.ScoreCard{
		CategoryScores: make(map[string]int),
	}

	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			card.CriticalCount++
		case types.SeverityHigh:
			card.HighCount++
		case types.SeverityMedium:
			card.MediumCount++
		case types.SeverityLow:
			card.LowCount++
		case types.SeverityInfo:
			card.InfoCount++
		}
		card.TotalFindings++
		cat := string(f.Category)
		card.CategoryScores[cat] += f.Severity.Score()
	}

	// Weighted penalty formula — prevents single category from collapsing the score.
	// Each severity tier contributes a capped penalty so the score stays meaningful
	// even in very unhealthy environments.
	critPenalty := min(40, card.CriticalCount*20)
	highPenalty := min(30, card.HighCount*8)
	medPenalty := min(20, card.MediumCount*4)
	lowPenalty := min(10, card.LowCount*1)
	totalPenalty := critPenalty + highPenalty + medPenalty + lowPenalty

	card.OverallScore = 100 - totalPenalty
	if card.OverallScore < 0 {
		card.OverallScore = 0
	}

	// Invert category scores to 0-100 scale (100 = no issues)
	for cat, rawPenalty := range card.CategoryScores {
		capped := rawPenalty * 3
		if capped > 100 {
			capped = 100
		}
		card.CategoryScores[cat] = 100 - capped
	}
	return card
}

// HTTP Handlers for querying findings

func (e *Engine) ListFindings(c *gin.Context) {
	query := `SELECT id, scan_id, indicator_id, name, severity, category, risk_score, detected_at, is_new
	          FROM findings ORDER BY detected_at DESC`
	args := []interface{}{}

	if scanID := c.Query("scan_id"); scanID != "" {
		query = `SELECT id, scan_id, indicator_id, name, severity, category, risk_score, detected_at, is_new
		         FROM findings WHERE scan_id=$1 ORDER BY
		         CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`
		args = append(args, scanID)
	}

	rows, err := e.db.Query(context.Background(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var findings []map[string]interface{}
	for rows.Next() {
		var id, scanID, indicatorID, name, severity, category string
		var riskScore int
		var detectedAt time.Time
		var isNew bool
		rows.Scan(&id, &scanID, &indicatorID, &name, &severity, &category, &riskScore, &detectedAt, &isNew)
		findings = append(findings, map[string]interface{}{
			"id": id, "scan_id": scanID, "indicator_id": indicatorID,
			"name": name, "severity": severity, "category": category,
			"risk_score": riskScore, "detected_at": detectedAt, "is_new": isNew,
		})
	}
	if findings == nil {
		findings = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
}

func (e *Engine) GetFinding(c *gin.Context) {
	id := c.Param("id")
	var f types.Finding
	var affectedJSON []byte
	var refs, mitre []string

	err := e.db.QueryRow(context.Background(),
		`SELECT id, scan_id, indicator_id, name, description, severity, category, risk_score,
		  affected_objects, remediation, "references", mitre, detected_at
		 FROM findings WHERE id=$1`, id,
	).Scan(&f.ID, &f.ScanID, &f.IndicatorID, &f.Name, &f.Description,
		&f.Severity, &f.Category, &f.RiskScore,
		&affectedJSON, &f.Remediation, &refs, &mitre, &f.DetectedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}

	json.Unmarshal(affectedJSON, &f.AffectedObjects)
	f.References = refs
	f.MITRE = mitre
	c.JSON(http.StatusOK, f)
}

func (e *Engine) GetFindingsByScan(c *gin.Context) {
	scanID := c.Param("scan_id")
	c.Request.URL.RawQuery = "scan_id=" + scanID
	e.ListFindings(c)
}

func (e *Engine) ListIndicators(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"indicators": types.AllIndicators,
		"total":      len(types.AllIndicators),
	})
}
