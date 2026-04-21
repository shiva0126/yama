// Collector Agent - runs on a domain-joined Windows machine.
// Exposes an HTTP API that the scan orchestrator calls to collect AD data.
// Executes PowerShell scripts and C# tools, returns JSON results.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ad-assessment/collector-agent/executor"
	"ad-assessment/collector-agent/handlers"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	port    := flag.String("port", "9090", "Agent HTTP port")
	psDir   := flag.String("ps-dir", "./powershell/modules", "PowerShell modules directory")
	csDir   := flag.String("cs-dir", "./csharp/bin", "C# tools directory")
	apiKey  := flag.String("api-key", os.Getenv("AGENT_API_KEY"), "API key for authentication")
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

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// API key auth middleware
	r.Use(func(c *gin.Context) {
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
			"version": "1.0.0",
			"capabilities": []string{
				"topology", "users", "groups", "computers",
				"gpos", "kerberos", "acls", "dcinfo", "trusts", "ous",
			},
		})
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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Agent shutting down")
}
