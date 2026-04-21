package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ad-assessment/scan-orchestrator/orchestrator"
	"ad-assessment/shared/config"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	cfg := config.Load()

	// DB
	pool, err := pgxpool.New(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("db connection failed: %v", err)
	}
	defer pool.Close()

	// Redis
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("invalid redis URL: %v", err)
	}
	rdb := redis.NewClient(opt)

	// Orchestrator
	orch := orchestrator.New(pool, rdb, cfg, logger)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "scan-orchestrator"})
	})

	// Scan endpoints
	r.GET("/scans", orch.ListScans)
	r.POST("/scans", orch.CreateScan)
	r.GET("/scans/:id", orch.GetScan)
	r.DELETE("/scans/:id", orch.CancelScan)
	r.GET("/scans/:id/progress", orch.GetProgress)
	r.GET("/scans/:id/scorecard", orch.GetScoreCard)

	// Agent endpoints
	r.GET("/agents", orch.ListAgents)
	r.POST("/agents", orch.RegisterAgent)
	r.GET("/agents/:id", orch.GetAgent)
	r.DELETE("/agents/:id", orch.DeleteAgent)
	r.GET("/agents/:id/status", orch.GetAgentStatus)

	// Internal: called by collector agent to report task results
	r.POST("/internal/task-result", orch.HandleTaskResult)

	srv := &http.Server{Addr: ":" + cfg.Port, Handler: r}
	go func() {
		logger.Info("Scan Orchestrator started", zap.String("port", cfg.Port))
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
