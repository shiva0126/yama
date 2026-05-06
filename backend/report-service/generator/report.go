package generator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"
	"time"

	"ad-assessment/shared/types"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type Generator struct {
	db           *pgxpool.Pool
	inventoryURL string
	analysisURL  string
	logger       *zap.Logger
	client       *http.Client
}

func New(db *pgxpool.Pool, inventoryURL, analysisURL string, logger *zap.Logger) *Generator {
	return &Generator{
		db:           db,
		inventoryURL: inventoryURL,
		analysisURL:  analysisURL,
		logger:       logger,
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

type GenerateRequest struct {
	ScanID string `json:"scan_id" binding:"required"`
	Format string `json:"format"` // html | json | pdf
}

type Report struct {
	ID          string          `json:"id"`
	ScanID      string          `json:"scan_id"`
	Format      string          `json:"format"`
	GeneratedAt time.Time       `json:"generated_at"`
	Domain      string          `json:"domain"`
	Score       int             `json:"score"`
	Findings    []types.Finding `json:"findings"`
	ScoreCard   types.ScoreCard `json:"score_card"`
}

func (g *Generator) Generate(c *gin.Context) {
	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Format == "" {
		req.Format = "html"
	}

	// Fetch scan metadata
	scan, err := g.fetchScan(req.ScanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}

	// Fetch findings
	findings, scoreCard, err := g.fetchFindings(req.ScanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch findings"})
		return
	}

	report := &Report{
		ID:          uuid.New().String(),
		ScanID:      req.ScanID,
		Format:      req.Format,
		GeneratedAt: time.Now(),
		Domain:      scan["domain"].(string),
		Score:       int(scan["overall_score"].(float64)),
		Findings:    findings,
		ScoreCard:   scoreCard,
	}

	// Persist report metadata
	g.db.Exec(context.Background(),
		`INSERT INTO reports (id, scan_id, format, domain, score, generated_at)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT DO NOTHING`,
		report.ID, report.ScanID, report.Format, report.Domain, report.Score, report.GeneratedAt,
	)

	c.JSON(http.StatusCreated, gin.H{
		"id":           report.ID,
		"scan_id":      report.ScanID,
		"format":       report.Format,
		"generated_at": report.GeneratedAt,
		"domain":       report.Domain,
		"score":        report.Score,
	})
}

func (g *Generator) Download(c *gin.Context) {
	reportID := c.Param("id")

	// Fetch report metadata from DB
	var scanID, format, domain string
	var score int
	var generatedAt time.Time
	err := g.db.QueryRow(context.Background(),
		`SELECT scan_id, format, domain, score, generated_at FROM reports WHERE id=$1`, reportID,
	).Scan(&scanID, &format, &domain, &score, &generatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}

	findings, scoreCard, err := g.fetchFindings(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch findings"})
		return
	}

	report := &Report{
		ID:          reportID,
		ScanID:      scanID,
		Format:      format,
		GeneratedAt: generatedAt,
		Domain:      domain,
		Score:       score,
		Findings:    findings,
		ScoreCard:   scoreCard,
	}

	switch format {
	case "json":
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="ad-report-%s.json"`, domain))
		c.JSON(http.StatusOK, report)
	case "html":
		html, err := renderHTML(report)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "render failed"})
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="ad-report-%s.html"`, domain))
		c.String(http.StatusOK, html)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported format"})
	}
}

func (g *Generator) GetReport(c *gin.Context) {
	id := c.Param("id")
	var scanID, format, domain string
	var score int
	var generatedAt time.Time
	err := g.db.QueryRow(context.Background(),
		`SELECT scan_id, format, domain, score, generated_at FROM reports WHERE id=$1`, id,
	).Scan(&scanID, &format, &domain, &score, &generatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": id, "scan_id": scanID, "format": format,
		"domain": domain, "score": score, "generated_at": generatedAt,
	})
}

func (g *Generator) ListReports(c *gin.Context) {
	rows, err := g.db.Query(context.Background(),
		`SELECT id, scan_id, format, domain, score, generated_at FROM reports ORDER BY generated_at DESC LIMIT 50`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var reports []map[string]interface{}
	for rows.Next() {
		var id, scanID, format, domain string
		var score int
		var generatedAt time.Time
		rows.Scan(&id, &scanID, &format, &domain, &score, &generatedAt)
		reports = append(reports, map[string]interface{}{
			"id": id, "scan_id": scanID, "format": format,
			"domain": domain, "score": score, "generated_at": generatedAt,
		})
	}
	if reports == nil {
		reports = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{"reports": reports, "total": len(reports)})
}

// ─── Internal helpers ────────────────────────────────────────

func (g *Generator) fetchScan(scanID string) (map[string]interface{}, error) {
	// inventoryURL is reused as proxy; use a dedicated scan URL via env if needed
	// For now use a fixed internal service URL overrideable via env
	scanURL := "http://scan-orchestrator:8081"
	resp, err := g.client.Get(fmt.Sprintf("%s/scans/%s", scanURL, scanID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var scan map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&scan)
	if scan["overall_score"] == nil {
		scan["overall_score"] = float64(0)
	}
	return scan, nil
}

func (g *Generator) fetchFindings(scanID string) ([]types.Finding, types.ScoreCard, error) {
	resp, err := g.client.Get(fmt.Sprintf("%s/findings/scan/%s", g.analysisURL, scanID))
	if err != nil {
		return nil, types.ScoreCard{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Findings []types.Finding `json:"findings"`
		Total    int             `json:"total"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, types.ScoreCard{}, err
	}

	// Compute scorecard from findings
	card := types.ScoreCard{OverallScore: 100, CategoryScores: make(map[string]int)}
	for _, f := range result.Findings {
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
		card.OverallScore -= f.Severity.Score()
	}
	if card.OverallScore < 0 {
		card.OverallScore = 0
	}
	return result.Findings, card, nil
}

// ─── HTML Report Template ─────────────────────────────────────

func renderHTML(r *Report) (string, error) {
	t, err := template.New("report").Funcs(template.FuncMap{
		"severityColor": func(s types.Severity) string {
			switch s {
			case types.SeverityCritical:
				return "#ef4444"
			case types.SeverityHigh:
				return "#f97316"
			case types.SeverityMedium:
				return "#f59e0b"
			case types.SeverityLow:
				return "#3b82f6"
			default:
				return "#6b7280"
			}
		},
		"upper": func(s types.Severity) string {
			str := string(s)
			b   := []byte(str)
			for i, c := range b {
				if c >= 'a' && c <= 'z' {
					b[i] = c - 32
				}
			}
			return string(b)
		},
		"string": func(s types.Severity) string { return string(s) },
	}).Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, r); err != nil {
		return "", err
	}
	return buf.String(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Assessment Report — {{.Domain}}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; padding: 40px 24px; }

  /* Header */
  .header { display: flex; align-items: center; justify-content: space-between; padding: 32px; background: #1e293b; border-radius: 16px; margin-bottom: 32px; border: 1px solid #334155; }
  .header-left h1 { font-size: 24px; font-weight: 700; color: #f8fafc; }
  .header-left p  { color: #94a3b8; margin-top: 4px; }
  .score-badge { width: 100px; height: 100px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; font-weight: 800; font-size: 32px; border: 4px solid; }

  /* Stats grid */
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; text-align: center; }
  .stat-card .value { font-size: 28px; font-weight: 800; }
  .stat-card .label { color: #94a3b8; font-size: 12px; margin-top: 4px; }

  /* Findings */
  .section-title { font-size: 16px; font-weight: 600; color: #f1f5f9; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #334155; }
  .finding { background: #1e293b; border: 1px solid #334155; border-radius: 12px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 12px; padding: 16px 20px; }
  .finding-id    { font-family: monospace; color: #64748b; font-size: 12px; width: 48px; flex-shrink: 0; }
  .severity-badge { font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 20px; flex-shrink: 0; letter-spacing: 0.05em; }
  .finding-name  { font-weight: 600; color: #f1f5f9; flex: 1; }
  .finding-body  { padding: 0 20px 16px 80px; }
  .finding-desc  { color: #94a3b8; font-size: 14px; margin-bottom: 12px; }
  .finding-section { margin-bottom: 10px; }
  .finding-section-title { font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 6px; }
  .affected-item { background: #0f172a; border-radius: 6px; padding: 6px 12px; font-size: 12px; font-family: monospace; margin-bottom: 4px; color: #cbd5e1; }
  .remediation   { background: #1e3a5f22; border-left: 3px solid #3b82f6; padding: 10px 14px; border-radius: 0 6px 6px 0; font-size: 13px; color: #93c5fd; }
  .mitre-badge   { display: inline-block; background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 2px 8px; font-size: 11px; font-family: monospace; color: #94a3b8; margin-right: 6px; }

  /* Meta */
  .meta { text-align: center; color: #475569; font-size: 12px; margin-top: 40px; padding-top: 24px; border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>AD Security Assessment</h1>
      <p>Domain: <strong style="color:#e2e8f0">{{.Domain}}</strong> &nbsp;|&nbsp; Generated: {{.GeneratedAt.Format "2006-01-02 15:04 UTC"}}</p>
    </div>
    {{$color := "#10b981"}}
    {{if lt .Score 80}}{{$color = "#f59e0b"}}{{end}}
    {{if lt .Score 60}}{{$color = "#f97316"}}{{end}}
    {{if lt .Score 40}}{{$color = "#ef4444"}}{{end}}
    <div class="score-badge" style="color:{{$color}};border-color:{{$color}}">
      {{.Score}}
      <span style="font-size:11px;font-weight:400;color:#94a3b8">/100</span>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats">
    <div class="stat-card">
      <div class="value" style="color:#ef4444">{{.ScoreCard.CriticalCount}}</div>
      <div class="label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:#f97316">{{.ScoreCard.HighCount}}</div>
      <div class="label">High</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:#f59e0b">{{.ScoreCard.MediumCount}}</div>
      <div class="label">Medium</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:#3b82f6">{{.ScoreCard.LowCount}}</div>
      <div class="label">Low</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:#8b5cf6">{{.ScoreCard.TotalFindings}}</div>
      <div class="label">Total</div>
    </div>
  </div>

  <!-- Findings -->
  <div class="section-title">Security Findings ({{len .Findings}})</div>
  {{range .Findings}}
  <div class="finding">
    <div class="finding-header">
      <span class="finding-id">{{.IndicatorID}}</span>
      <span class="severity-badge" style="background:{{severityColor .Severity}}22; color:{{severityColor .Severity}}">{{upper .Severity}}</span>
      <span class="finding-name">{{.Name}}</span>
    </div>
    <div class="finding-body">
      <div class="finding-desc">{{.Description}}</div>

      {{if .AffectedObjects}}
      <div class="finding-section">
        <div class="finding-section-title">Affected Objects ({{len .AffectedObjects}})</div>
        {{range .AffectedObjects}}
        <div class="affected-item"><span style="color:#64748b;width:70px;display:inline-block">{{.Type}}</span> {{.Name}}{{if .Detail}} — <span style="color:#64748b">{{.Detail}}</span>{{end}}</div>
        {{end}}
      </div>
      {{end}}

      <div class="finding-section">
        <div class="finding-section-title">Remediation</div>
        <div class="remediation">{{.Remediation}}</div>
      </div>

      {{if .MITRE}}
      <div class="finding-section" style="margin-top:8px">
        {{range .MITRE}}<span class="mitre-badge">{{.}}</span>{{end}}
      </div>
      {{end}}
    </div>
  </div>
  {{else}}
  <p style="color:#64748b;text-align:center;padding:40px">No findings recorded for this scan.</p>
  {{end}}

  <div class="meta">AD Sentinel Assessment Platform &nbsp;·&nbsp; Report ID: {{.ID}}</div>
</div>
</body>
</html>`
