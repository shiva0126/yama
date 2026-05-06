package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port        string
	RedisURL    string
	DBDSN       string
	JWTSecret   string
	Env         string

	// Service URLs (used by API Gateway)
	ScanOrchestratorURL string
	InventoryServiceURL string
	AnalysisEngineURL   string
	ReportServiceURL    string
}

func Load() *Config {
	return &Config{
		Port:                getEnv("PORT", "8080"),
		RedisURL:            getEnv("REDIS_URL", "redis://:redis_secret@localhost:6379/0"),
		DBDSN:               getEnv("DB_DSN", "postgres://adassess:adassess_secret@localhost:5432/adassessment?sslmode=disable"),
		JWTSecret:           getEnv("JWT_SECRET", "change_this_in_production"),
		Env:                 getEnv("ENV", "development"),
		ScanOrchestratorURL: getEnv("SCAN_ORCHESTRATOR_URL", "http://localhost:8081"),
		InventoryServiceURL: getEnv("INVENTORY_SERVICE_URL", "http://localhost:8082"),
		AnalysisEngineURL:   getEnv("ANALYSIS_ENGINE_URL", "http://localhost:8083"),
		ReportServiceURL:    getEnv("REPORT_SERVICE_URL", "http://localhost:8084"),
	}
}

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultValue
}
