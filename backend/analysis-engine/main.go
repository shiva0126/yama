package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ad-assessment/analysis-engine/engine"
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

	pool, err := pgxpool.New(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("db connection failed: %v", err)
	}
	defer pool.Close()

	opt, _ := redis.ParseURL(cfg.RedisURL)
	rdb := redis.NewClient(opt)

	eng := engine.New(pool, rdb, cfg.InventoryServiceURL, logger)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "analysis-engine"})
	})

	// Triggered by scan-orchestrator after collection completes
	r.POST("/analyze", eng.Analyze)

	// Query findings
	r.GET("/findings", eng.ListFindings)
	r.GET("/findings/:id", eng.GetFinding)
	r.GET("/findings/scan/:scan_id", eng.GetFindingsByScan)
	r.GET("/indicators", eng.ListIndicators)

	srv := &http.Server{Addr: ":" + cfg.Port, Handler: r}
	go func() {
		logger.Info("Analysis Engine started", zap.String("port", cfg.Port))
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
