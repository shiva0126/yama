package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ad-assessment/api-gateway/handlers"
	"ad-assessment/api-gateway/middleware"
	"ad-assessment/api-gateway/websocket"
	"ad-assessment/shared/config"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	cfg := config.Load()

	// Redis client
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("invalid redis URL: %v", err)
	}
	rdb := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis connection failed: %v", err)
	}

	// WebSocket hub (broadcasts scan progress to all connected frontends)
	wsHub := websocket.NewHub(rdb, logger)
	go wsHub.Run()

	// Gin router
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
	}))

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "api-gateway"})
	})

	// WebSocket endpoint for real-time frontend updates
	r.GET("/ws", func(c *gin.Context) {
		wsHub.ServeWS(c.Writer, c.Request)
	})

	// API v1 routes
	api := r.Group("/api/v1")
	{
		// Auth (basic JWT for now)
		auth := api.Group("/auth")
		{
			authHandler := handlers.NewAuthHandler(cfg.JWTSecret, logger)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.Refresh)
		}

		// Protected routes
		protected := api.Group("")
		protected.Use(middleware.JWTAuth(cfg.JWTSecret))
		{
			// Agents
			agentHandler := handlers.NewAgentHandler(cfg.ScanOrchestratorURL, logger)
			agents := protected.Group("/agents")
			{
				agents.GET("", agentHandler.ListAgents)
				agents.POST("", agentHandler.RegisterAgent)
				agents.GET("/:id", agentHandler.GetAgent)
				agents.DELETE("/:id", agentHandler.DeleteAgent)
				agents.GET("/:id/status", agentHandler.GetAgentStatus)
				agents.POST("/install", agentHandler.InstallAgent)
				agents.GET("/install", agentHandler.ListInstallJobs)
				agents.GET("/install/:jobId", agentHandler.GetInstallStatus)
			}

			// Scans
			scanHandler := handlers.NewScanHandler(cfg.ScanOrchestratorURL, logger)
			scans := protected.Group("/scans")
			{
				scans.GET("", scanHandler.ListScans)
				scans.POST("", scanHandler.CreateScan)
				scans.GET("/:id", scanHandler.GetScan)
				scans.DELETE("/:id", scanHandler.CancelScan)
				scans.GET("/:id/progress", scanHandler.GetProgress)
				scans.GET("/:id/scorecard", scanHandler.GetScoreCard)
			}

			// Inventory
			inventoryHandler := handlers.NewInventoryHandler(cfg.InventoryServiceURL, logger)
			inventory := protected.Group("/inventory")
			{
				inventory.GET("/snapshots", inventoryHandler.ListSnapshots)
				inventory.GET("/snapshots/:id", inventoryHandler.GetSnapshot)
				inventory.GET("/snapshots/:id/users", inventoryHandler.GetUsers)
				inventory.GET("/snapshots/:id/groups", inventoryHandler.GetGroups)
				inventory.GET("/snapshots/:id/computers", inventoryHandler.GetComputers)
				inventory.GET("/snapshots/:id/gpos", inventoryHandler.GetGPOs)
				inventory.GET("/snapshots/:id/dcs", inventoryHandler.GetDomainControllers)
				inventory.GET("/snapshots/:id/trusts", inventoryHandler.GetTrusts)
				inventory.GET("/snapshots/:id/topology", inventoryHandler.GetTopology)
				inventory.GET("/snapshots/:id/cert-templates", inventoryHandler.GetCertTemplates)
				inventory.GET("/snapshots/:id/cert-authorities", inventoryHandler.GetCertAuthorities)
			}

			// Findings
			findingsHandler := handlers.NewFindingsHandler(cfg.AnalysisEngineURL, logger)
			findings := protected.Group("/findings")
			{
				findings.GET("", findingsHandler.ListFindings)
				findings.GET("/:id", findingsHandler.GetFinding)
				findings.GET("/scan/:scan_id", findingsHandler.GetFindingsByScan)
				findings.GET("/indicators", findingsHandler.ListIndicators)
			}

			// Reports
			reportHandler := handlers.NewReportHandler(cfg.ReportServiceURL, logger)
			reports := protected.Group("/reports")
			{
				reports.GET("", reportHandler.ListReports)
				reports.POST("/generate", reportHandler.Generate)
				reports.GET("/:id", reportHandler.GetReport)
				reports.GET("/:id/download", reportHandler.Download)
			}
		}
	}

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		logger.Info("API Gateway started", zap.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	srv.Shutdown(ctx2)
	logger.Info("API Gateway shut down")
}
