package config

import "os"

// Config centralizes shared environment variables for the new defense-plane services.
// Each service can embed or extend this configuration instead of redefining the same
// connection and transport settings repeatedly.
type Config struct {
	ServiceName string
	HTTPPort    string
	GRPCPort    string

	DBDSN         string
	RedisURL      string
	NATSURL       string
	MinIOEndpoint string
	MinIOBucket   string
	MinIOAccessKey string
	MinIOSecretKey string
}

func Load(serviceName, defaultHTTPPort, defaultGRPCPort string) *Config {
	return &Config{
		ServiceName:    serviceName,
		HTTPPort:       getEnv("HTTP_PORT", defaultHTTPPort),
		GRPCPort:       getEnv("GRPC_PORT", defaultGRPCPort),
		DBDSN:          getEnv("DB_DSN", "postgres://adassess:adassess_secret@localhost:5432/adassessment?sslmode=disable"),
		RedisURL:       getEnv("REDIS_URL", "redis://:redis_secret@localhost:6379/0"),
		NATSURL:        getEnv("NATS_URL", "nats://localhost:4222"),
		MinIOEndpoint:  getEnv("MINIO_ENDPOINT", "localhost:9000"),
		MinIOBucket:    getEnv("MINIO_BUCKET", "yama-evidence"),
		MinIOAccessKey: getEnv("MINIO_ACCESS_KEY", "minioadmin"),
		MinIOSecretKey: getEnv("MINIO_SECRET_KEY", "minioadmin"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
