package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

func main() {
	portFlag := flag.Int("port", 0, "Port to listen on (overrides PHONELINK_PORT)")
	hostFlag := flag.String("host", "", "Host to bind on (overrides PHONELINK_HOST)")
	flag.Parse()

	cfg := server.DefaultConfig()

	if *hostFlag != "" {
		cfg.Host = *hostFlag
	} else if envHost := os.Getenv("PHONELINK_HOST"); envHost != "" {
		cfg.Host = envHost
	}

	if *portFlag != 0 {
		cfg.Port = *portFlag
	} else if envPort := os.Getenv("PHONELINK_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			cfg.Port = p
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	srv := server.NewServer(cfg, logger)

	// Graceful shutdown channel
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server start error", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info(fmt.Sprintf("%s started on %s:%d", server.Name, cfg.Host, cfg.Port))

	<-shutdownChan
	logger.Info("Shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server shutdown failed", "error", err)
	} else {
		logger.Info("Server stopped cleanly")
	}
}
