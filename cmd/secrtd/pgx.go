package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Simple abstraction to get database connections. You should generally use
// the initialised PGXPool to obtain database connections, but for some use cases
// (specifically, notifications), you can connect directly using Connect().

var PGXPool *pgxpool.Pool

func noticeHandler(conn *pgconn.PgConn, notice *pgconn.Notice) {
	log.Printf("NOTICE: %s", notice.Message)
}

func StartPGXPool(dsn string) error {
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("unable to configure connection pool: %w", err)
	}

	// Set the hook for receiving RAISE NOTICE messages.
	poolConfig.ConnConfig.OnNotice = noticeHandler

	// Create the pool
	PGXPool, err = pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return fmt.Errorf("unable to connect to the database: %w", err)
	}

	return nil
}

func mustInitPGX() {
	// Initialise the connection pool - connecting to the upgraded database
	if err := StartPGXPool(Config.DatabaseDSN); err != nil {
		panic(err)
	}
}
