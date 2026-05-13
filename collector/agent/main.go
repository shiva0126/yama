// Collector Agent - runs on a domain-joined Windows machine.
// Exposes an HTTP API that the scan orchestrator calls to collect AD data.
// Executes PowerShell scripts and C# tools, returns JSON results.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"ad-assessment/collector-agent/executor"
	"ad-assessment/collector-agent/handlers"
	"ad-assessment/collector-agent/sensor"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	port    := flag.String("port", "9090", "Agent HTTP port")
	psDir   := flag.String("ps-dir", "./powershell/modules", "PowerShell modules directory")
	csDir   := flag.String("cs-dir", "./csharp/bin", "C# tools directory")
	apiKey  := flag.String("api-key", os.Getenv("AGENT_API_KEY"), "API key for authentication")
	agentID := flag.String("agent-id", os.Getenv("AGENT_ID"), "Agent UUID")
	flag.Parse()

	if *apiKey == "" {
		log.Fatal("api-key is required. Set via --api-key flag or AGENT_API_KEY env var")
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Executor handles PS/C# execution
	exec := executor.New(*psDir, *csDir, logger)

	// Request handlers
	h := handlers.New(exec, logger)

	// Sensor: start host-level event collection (ETW on Windows, no-op elsewhere)
	hostname, _ := os.Hostname()
	domain := os.Getenv("AGENT_DOMAIN")
	agentSensor := sensor.New(*agentID, domain, hostname, sensor.EnvSignalCollectorURL(), logger)
	sensorCtx, sensorCancel := context.WithCancel(context.Background())
	defer sensorCancel()
	agentSensor.Start(sensorCtx)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// API key auth middleware
	r.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}
		key := c.GetHeader("X-API-Key")
		if key != *apiKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			return
		}
		c.Next()
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "collector-agent",
			"version": "1.2.0",
			"capabilities": []string{
				"topology", "users", "groups", "computers",
				"gpos", "kerberos", "acls", "dcinfo", "trusts", "ous", "fgpp", "adcs", "sites",
				"service-identities", "ad-vuln-scan",
				"defense:signal-forward", "defense:status", "defense:execute",
				"sensor:etw", "sensor:process-watch", "sensor:service-watch", "sensor:sysmon",
			},
			"defense_mode": os.Getenv("DEFENSE_MODE") == "true",
			"platform":     runtime.GOOS,
		})
	})

	r.GET("/sensor/health", func(c *gin.Context) {
		h := agentSensor.Health()
		c.JSON(http.StatusOK, h)
	})

	// Collection endpoints — each maps to a PowerShell module
	collect := r.Group("/collect")
	{
		collect.POST("/topology",  h.CollectTopology)
		collect.POST("/users",     h.CollectUsers)
		collect.POST("/groups",    h.CollectGroups)
		collect.POST("/computers", h.CollectComputers)
		collect.POST("/gpos",      h.CollectGPOs)
		collect.POST("/kerberos",  h.CollectKerberos)
		collect.POST("/acls",      h.CollectACLs)
		collect.POST("/dcinfo",    h.CollectDCInfo)
		collect.POST("/trusts",    h.CollectTrusts)
		collect.POST("/ous",       h.CollectOUs)
		collect.POST("/fgpp",      h.CollectFGPP)
	}

	// Defense endpoints — forward signals to the Yama signal-collector service
	defend := r.Group("/defend")
	{
		defend.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"defense_mode":   os.Getenv("DEFENSE_MODE") == "true",
				"signal_backend": os.Getenv("SIGNAL_COLLECTOR_URL"),
				"agent_id":       os.Getenv("AGENT_ID"),
				"capabilities":   []string{"signal-forward", "account-disable", "audit-log"},
			})
		})

		defend.POST("/signal", h.ForwardSignal)
		defend.POST("/execute", h.DefendExecute)
	}

	srv := &http.Server{
		Addr:         ":" + *port,
		Handler:      r,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second,
	}

	go func() {
		logger.Info("Collector Agent started",
			zap.String("port", *port),
			zap.String("ps_dir", *psDir),
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("agent error", zap.Error(err))
		}
	}()

	go runDefenseHeartbeat(logger, *port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Agent shutting down")
}

func runDefenseHeartbeat(logger *zap.Logger, port string) {
	if os.Getenv("DEFENSE_MODE") != "true" {
		return
	}

	agentID := strings.TrimSpace(os.Getenv("AGENT_ID"))
	if agentID == "" {
		logger.Warn("DEFENSE_MODE=true but AGENT_ID is not set; heartbeat disabled")
		return
	}

	defenseAPI := strings.TrimRight(strings.TrimSpace(os.Getenv("DEFENSE_API_URL")), "/")
	if defenseAPI == "" {
		defenseAPI = "http://defense-api:8098"
	}

	defenseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("DEFENSE_URL")), "/")
	if defenseURL == "" {
		defenseURL = "http://collector-agent:" + port
	}

	send := func() {
		payload, _ := json.Marshal(map[string]string{
			"agent_id":    agentID,
			"defense_url": defenseURL,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, defenseAPI+"/agent/heartbeat", bytes.NewReader(payload))
		if err != nil {
			logger.Warn("heartbeat request build failed", zap.Error(err))
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Warn("heartbeat send failed", zap.Error(err))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 {
			logger.Warn("heartbeat rejected", zap.Int("status", resp.StatusCode))
			return
		}
		logger.Debug("heartbeat sent", zap.String("agent_id", agentID), zap.String("defense_api", defenseAPI))
	}

	send()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		send()
	}
}
