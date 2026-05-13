package handlers

// proxy.go - Generic HTTP proxy helper for forwarding requests to microservices

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

func proxyGET(c *gin.Context, serviceURL, path string, logger *zap.Logger) {
	resp, err := httpClient.Get(serviceURL + path)
	if err != nil {
		logger.Error("proxy GET failed", zap.String("url", serviceURL+path), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upstream service unavailable"})
		return
	}
	defer resp.Body.Close()
	forwardResponse(c, resp)
}

func proxyGETWithQuery(c *gin.Context, serviceURL, path string, logger *zap.Logger) {
	url := serviceURL + path
	if c.Request.URL.RawQuery != "" {
		url += "?" + c.Request.URL.RawQuery
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		logger.Error("proxy GET failed", zap.String("url", url), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upstream service unavailable"})
		return
	}
	defer resp.Body.Close()
	forwardResponse(c, resp)
}

func proxyPOST(c *gin.Context, serviceURL, path string, logger *zap.Logger) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	req, err := http.NewRequest(http.MethodPost, serviceURL+path, bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error("proxy POST failed", zap.String("url", serviceURL+path), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upstream service unavailable"})
		return
	}
	defer resp.Body.Close()
	forwardResponse(c, resp)
}

func proxyDELETE(c *gin.Context, serviceURL, path string, logger *zap.Logger) {
	req, err := http.NewRequest(http.MethodDelete, serviceURL+path, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error("proxy DELETE failed", zap.String("url", serviceURL+path), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upstream service unavailable"})
		return
	}
	defer resp.Body.Close()
	forwardResponse(c, resp)
}

func forwardResponse(c *gin.Context, resp *http.Response) {
	body, _ := io.ReadAll(resp.Body)
	c.Header("Content-Type", "application/json")
	c.Status(resp.StatusCode)
	c.Writer.Write(body)
}

// AuthHandler for JWT login
type AuthHandler struct {
	jwtSecret string
	logger    *zap.Logger
}

func NewAuthHandler(jwtSecret string, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{jwtSecret: jwtSecret, logger: logger}
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login - simple local auth (extend with LDAP/AD auth for production)
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Validate against user store / LDAP
	// For now accept admin/admin in dev
	if req.Username != "admin" || req.Password != "admin" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := generateJWT(req.Username, h.jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_in": 86400,
		"username":   req.Username,
	})
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	// TODO: implement refresh token logic
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// generateJWT produces a signed HS256 JWT (RFC 7519) using stdlib crypto only.
func generateJWT(username, secret string) (string, error) {
	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"sub":      username,
		"username": username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigInput := header + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig, nil
}

// ParseJWTClaims validates an HS256 JWT and returns the payload claims.
func ParseJWTClaims(token, secret string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sigInput))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, fmt.Errorf("invalid signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token expired")
		}
	}
	return claims, nil
}

// ScanHandler proxies to scan-orchestrator
type ScanHandler struct {
	serviceURL string
	logger     *zap.Logger
}

func NewScanHandler(serviceURL string, logger *zap.Logger) *ScanHandler {
	return &ScanHandler{serviceURL: serviceURL, logger: logger}
}
func (h *ScanHandler) ListScans(c *gin.Context)    { proxyGETWithQuery(c, h.serviceURL, "/scans", h.logger) }
func (h *ScanHandler) CreateScan(c *gin.Context)   { proxyPOST(c, h.serviceURL, "/scans", h.logger) }
func (h *ScanHandler) GetScan(c *gin.Context)      { proxyGET(c, h.serviceURL, "/scans/"+c.Param("id"), h.logger) }
func (h *ScanHandler) CancelScan(c *gin.Context)   { proxyDELETE(c, h.serviceURL, "/scans/"+c.Param("id"), h.logger) }
func (h *ScanHandler) GetProgress(c *gin.Context)  { proxyGET(c, h.serviceURL, "/scans/"+c.Param("id")+"/progress", h.logger) }
func (h *ScanHandler) GetScoreCard(c *gin.Context) { proxyGET(c, h.serviceURL, "/scans/"+c.Param("id")+"/scorecard", h.logger) }

// AgentHandler proxies to scan-orchestrator agent management
type AgentHandler struct {
	serviceURL string
	logger     *zap.Logger
}

func NewAgentHandler(serviceURL string, logger *zap.Logger) *AgentHandler {
	return &AgentHandler{serviceURL: serviceURL, logger: logger}
}
func (h *AgentHandler) ListAgents(c *gin.Context)     { proxyGET(c, h.serviceURL, "/agents", h.logger) }
func (h *AgentHandler) RegisterAgent(c *gin.Context)  { proxyPOST(c, h.serviceURL, "/agents", h.logger) }
func (h *AgentHandler) GetAgent(c *gin.Context)       { proxyGET(c, h.serviceURL, "/agents/"+c.Param("id"), h.logger) }
func (h *AgentHandler) DeleteAgent(c *gin.Context)    { proxyDELETE(c, h.serviceURL, "/agents/"+c.Param("id"), h.logger) }
func (h *AgentHandler) GetAgentStatus(c *gin.Context) { proxyGET(c, h.serviceURL, "/agents/"+c.Param("id")+"/status", h.logger) }
func (h *AgentHandler) InstallAgent(c *gin.Context)      { proxyPOST(c, h.serviceURL, "/agents/install", h.logger) }
func (h *AgentHandler) InstallBulkDCs(c *gin.Context)    { proxyPOST(c, h.serviceURL, "/agents/install/bulk-dcs", h.logger) }
func (h *AgentHandler) ListInstallJobs(c *gin.Context)   { proxyGET(c, h.serviceURL, "/agents/install", h.logger) }
func (h *AgentHandler) GetInstallStatus(c *gin.Context)  { proxyGET(c, h.serviceURL, "/agents/install/"+c.Param("jobId"), h.logger) }

// InventoryHandler proxies to inventory-service
type InventoryHandler struct {
	serviceURL string
	logger     *zap.Logger
}

func NewInventoryHandler(serviceURL string, logger *zap.Logger) *InventoryHandler {
	return &InventoryHandler{serviceURL: serviceURL, logger: logger}
}
func (h *InventoryHandler) ListSnapshots(c *gin.Context)       { proxyGETWithQuery(c, h.serviceURL, "/snapshots", h.logger) }
func (h *InventoryHandler) GetSnapshot(c *gin.Context)         { proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id"), h.logger) }
func (h *InventoryHandler) GetUsers(c *gin.Context)            { proxyGETWithQuery(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/users", h.logger) }
func (h *InventoryHandler) GetGroups(c *gin.Context)           { proxyGETWithQuery(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/groups", h.logger) }
func (h *InventoryHandler) GetComputers(c *gin.Context)        { proxyGETWithQuery(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/computers", h.logger) }
func (h *InventoryHandler) GetGPOs(c *gin.Context)             { proxyGETWithQuery(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/gpos", h.logger) }
func (h *InventoryHandler) GetDomainControllers(c *gin.Context){ proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/dcs", h.logger) }
func (h *InventoryHandler) GetTrusts(c *gin.Context)           { proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/trusts", h.logger) }
func (h *InventoryHandler) GetTopology(c *gin.Context)         { proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/topology", h.logger) }
func (h *InventoryHandler) GetCertTemplates(c *gin.Context)    { proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/cert-templates", h.logger) }
func (h *InventoryHandler) GetCertAuthorities(c *gin.Context)  { proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/cert-authorities", h.logger) }
func (h *InventoryHandler) GetServiceIdentities(c *gin.Context){ proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/service-identities", h.logger) }
func (h *InventoryHandler) GetVulnerabilities(c *gin.Context)  { proxyGET(c, h.serviceURL, "/snapshots/"+c.Param("id")+"/vulnerabilities", h.logger) }

// FindingsHandler proxies to analysis-engine
type FindingsHandler struct {
	serviceURL string
	logger     *zap.Logger
}

func NewFindingsHandler(serviceURL string, logger *zap.Logger) *FindingsHandler {
	return &FindingsHandler{serviceURL: serviceURL, logger: logger}
}
func (h *FindingsHandler) ListFindings(c *gin.Context)       { proxyGETWithQuery(c, h.serviceURL, "/findings", h.logger) }
func (h *FindingsHandler) GetFinding(c *gin.Context)         { proxyGET(c, h.serviceURL, "/findings/"+c.Param("id"), h.logger) }
func (h *FindingsHandler) GetFindingsByScan(c *gin.Context)  { proxyGETWithQuery(c, h.serviceURL, "/findings/scan/"+c.Param("scan_id"), h.logger) }
func (h *FindingsHandler) ListIndicators(c *gin.Context)     { proxyGET(c, h.serviceURL, "/indicators", h.logger) }

// ReportHandler proxies to report-service
type ReportHandler struct {
	serviceURL string
	logger     *zap.Logger
}

func NewReportHandler(serviceURL string, logger *zap.Logger) *ReportHandler {
	return &ReportHandler{serviceURL: serviceURL, logger: logger}
}
func (h *ReportHandler) Generate(c *gin.Context)     { proxyPOST(c, h.serviceURL, "/reports/generate", h.logger) }
func (h *ReportHandler) GetReport(c *gin.Context)    { proxyGET(c, h.serviceURL, "/reports/"+c.Param("id"), h.logger) }
func (h *ReportHandler) Download(c *gin.Context)     { proxyGET(c, h.serviceURL, "/reports/"+c.Param("id")+"/download", h.logger) }
func (h *ReportHandler) ListReports(c *gin.Context)  { proxyGET(c, h.serviceURL, "/reports", h.logger) }
