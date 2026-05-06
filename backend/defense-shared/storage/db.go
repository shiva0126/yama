package storage

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a PostgreSQL pool for the defense plane services.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	return pgxpool.New(ctx, dsn)
}
