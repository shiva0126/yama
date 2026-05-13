package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"ad-assessment/shared/types"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type OverviewHandler struct {
	scansURL     string
	agentsURL    string
	findingsURL  string
	reportsURL   string
	logger       *zap.Logger
}

func NewOverviewHandler(scansURL, agentsURL, findingsURL, reportsURL string, logger *zap.Logger) *OverviewHandler {
	return &OverviewHandler{
		scansURL:    scansURL,
		agentsURL:   agentsURL,
		findingsURL: findingsURL,
		reportsURL:  reportsURL,
		logger:      logger,
	}
}

type OverviewSummary struct {
	GeneratedAt time.Time `json:"generated_at"`
	Collectors  struct {
		Total   int              `json:"total"`
		Online  int              `json:"online"`
		Busy    int              `json:"busy"`
		Offline int              `json:"offline"`
		Stale   int              `json:"stale"`
		Recent  []types.CollectorAgent `json:"recent"`
	} `json:"collectors"`
	Scans struct {
		Total          int              `json:"total"`
		Running        int              `json:"running"`
		Completed      int              `json:"completed"`
		Failed         int              `json:"failed"`
		LatestCompleted *types.ScanJob   `json:"latest_completed,omitempty"`
		Recent         []types.ScanJob   `json:"recent"`
	} `json:"scans"`
	Findings struct {
		Total      int               `json:"total"`
		Critical   int               `json:"critical"`
		High       int               `json:"high"`
		Medium     int               `json:"medium"`
		Low        int               `json:"low"`
		Info       int               `json:"info"`
		New        int               `json:"new"`
		Coverage   CoverageSummary   `json:"coverage"`
		Top        []types.Finding   `json:"top"`
	} `json:"findings"`
	Reports struct {
		Total int                   `json:"total"`
		Recent []ReportSummary      `json:"recent"`
	} `json:"reports"`
}

type CoverageSummary struct {
	Covered    int `json:"covered"`
	Total      int `json:"total"`
	Percentage int `json:"percentage"`
}

type ReportSummary struct {
	ID          string    `json:"id"`
	ScanID      string    `json:"scan_id"`
	Format      string    `json:"format"`
	Domain      string    `json:"domain"`
	Score       int       `json:"score"`
	GeneratedAt time.Time `json:"generated_at"`
}

func (h *OverviewHandler) Summary(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	var scansResp struct {
		Scans []types.ScanJob `json:"scans"`
		Total int             `json:"total"`
	}
	if err := fetchJSON(ctx, h.scansURL+"/scans", &scansResp); err != nil {
		h.logger.Error("overview scans fetch failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to load scans"})
		return
	}

	var agentsResp struct {
		Agents []types.CollectorAgent `json:"agents"`
		Total  int                    `json:"total"`
	}
	if err := fetchJSON(ctx, h.agentsURL+"/agents", &agentsResp); err != nil {
		h.logger.Error("overview agents fetch failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to load agents"})
		return
	}

	var reportsResp struct {
		Reports []ReportSummary `json:"reports"`
		Total   int             `json:"total"`
	}
	if err := fetchJSON(ctx, h.reportsURL+"/reports", &reportsResp); err != nil {
		h.logger.Error("overview reports fetch failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to load reports"})
		return
	}

	var findingsResp struct {
		Findings []types.Finding `json:"findings"`
		Total    int             `json:"total"`
	}

	var indicatorsResp struct {
		Indicators []types.SecurityIndicator `json:"indicators"`
		Total      int                       `json:"total"`
	}
	if err := fetchJSON(ctx, h.findingsURL+"/indicators", &indicatorsResp); err != nil {
		h.logger.Error("overview indicators fetch failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to load indicator catalog"})
		return
	}

	var latestCompleted *types.ScanJob
	for i := range scansResp.Scans {
		scan := scansResp.Scans[i]
		if scan.Status == types.ScanStatusRunning {
			continue
		}
		if scan.Status == types.ScanStatusCompleted {
			if latestCompleted == nil || compareScanTime(scan.CompletedAt, latestCompleted.CompletedAt) > 0 {
				copyScan := scan
				latestCompleted = &copyScan
			}
		}
	}

	if latestCompleted != nil {
		if err := fetchJSON(ctx, h.findingsURL+"/findings/scan/"+latestCompleted.ID, &findingsResp); err != nil {
			h.logger.Error("overview findings fetch failed", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to load findings"})
			return
		}
	}

	summary := OverviewSummary{GeneratedAt: time.Now().UTC()}
	summary.Collectors.Total = len(agentsResp.Agents)
	summary.Collectors.Recent = truncateAgents(agentsResp.Agents, 6)
	summary.Collectors.Online, summary.Collectors.Busy, summary.Collectors.Offline, summary.Collectors.Stale = collectorCounts(agentsResp.Agents)

	summary.Scans.Total = len(scansResp.Scans)
	summary.Scans.Recent = truncateScans(scansResp.Scans, 8)
	for _, scan := range scansResp.Scans {
		switch scan.Status {
		case types.ScanStatusRunning:
			summary.Scans.Running++
		case types.ScanStatusCompleted:
			summary.Scans.Completed++
		case types.ScanStatusFailed:
			summary.Scans.Failed++
		}
	}
	if latestCompleted != nil {
		summary.Scans.LatestCompleted = latestCompleted
	}

	summary.Reports.Total = len(reportsResp.Reports)
	summary.Reports.Recent = truncateReports(reportsResp.Reports, 6)

	summary.Findings.Total = len(findingsResp.Findings)
	summary.Findings.Coverage = coverageSummary(findingsResp.Findings, indicatorsResp.Total)
	summary.Findings.Top = topFindings(findingsResp.Findings, 6)
	for _, finding := range findingsResp.Findings {
		switch finding.Severity {
		case "critical":
			summary.Findings.Critical++
		case "high":
			summary.Findings.High++
		case "medium":
			summary.Findings.Medium++
		case "low":
			summary.Findings.Low++
		case "info":
			summary.Findings.Info++
		}
		if finding.IsNew {
			summary.Findings.New++
		}
	}

	c.JSON(http.StatusOK, summary)
}

func fetchJSON(ctx context.Context, url string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &httpError{status: resp.StatusCode}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type httpError struct{ status int }

func (e *httpError) Error() string { return http.StatusText(e.status) }

func compareScanTime(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	case a.After(*b):
		return 1
	case a.Before(*b):
		return -1
	default:
		return 0
	}
}

func truncateScans(scans []types.ScanJob, limit int) []types.ScanJob {
	if len(scans) <= limit {
		return scans
	}
	return scans[:limit]
}

func truncateAgents(agents []types.CollectorAgent, limit int) []types.CollectorAgent {
	if len(agents) <= limit {
		return agents
	}
	return agents[:limit]
}

func truncateReports(reports []ReportSummary, limit int) []ReportSummary {
	if len(reports) <= limit {
		return reports
	}
	return reports[:limit]
}

func collectorCounts(agents []types.CollectorAgent) (online, busy, offline, stale int) {
	for _, agent := range agents {
		switch agent.Status {
		case "online":
			online++
		case "busy":
			busy++
		default:
			offline++
		}
		if !agent.LastSeen.IsZero() && time.Since(agent.LastSeen) > 24*time.Hour {
			stale++
		}
	}
	return
}

func coverageSummary(findings []types.Finding, total int) CoverageSummary {
	coveredIDs := map[string]struct{}{}
	for _, finding := range findings {
		if finding.IndicatorID != "" {
			coveredIDs[finding.IndicatorID] = struct{}{}
		}
	}
	covered := len(coveredIDs)
	percentage := 0
	if total > 0 {
		percentage = int(float64(covered) / float64(total) * 100)
	}
	return CoverageSummary{Covered: covered, Total: total, Percentage: percentage}
}

func topFindings(findings []types.Finding, limit int) []types.Finding {
	list := append([]types.Finding(nil), findings...)
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Severity == list[j].Severity {
			if list[i].RiskScore == list[j].RiskScore {
				return list[i].DetectedAt.After(list[j].DetectedAt)
			}
			return list[i].RiskScore > list[j].RiskScore
		}
		return severityRank(string(list[i].Severity)) > severityRank(string(list[j].Severity))
	})
	if len(list) > limit {
		return list[:limit]
	}
	return list
}

func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
