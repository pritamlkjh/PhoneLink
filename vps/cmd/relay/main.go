package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

func main() {
	portFlag := flag.Int("port", 0, "Port to listen on (overrides PHONELINK_PORT)")
	hostFlag := flag.String("host", "", "Host to bind on (overrides PHONELINK_HOST)")
	dataDirFlag := flag.String("data-dir", "", "Directory for persistent registry state (overrides PHONELINK_DATA_DIR)")
	tlsCertFlag := flag.String("tls-cert", "", "Path to TLS certificate PEM (overrides PHONELINK_TLS_CERT)")
	tlsKeyFlag := flag.String("tls-key", "", "Path to TLS private key PEM (overrides PHONELINK_TLS_KEY)")
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
		p, err := strconv.Atoi(envPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid PHONELINK_PORT %q: %v\n", envPort, err)
			os.Exit(1)
		}
		cfg.Port = p
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		fmt.Fprintf(os.Stderr, "invalid port %d: must be in range 1..65535\n", cfg.Port)
		os.Exit(1)
	}

	dataDir := *dataDirFlag
	if dataDir == "" {
		dataDir = os.Getenv("PHONELINK_DATA_DIR")
	}
	if dataDir != "" {
		cfg.StateFile = filepath.Join(dataDir, "registry_state.json")
	}

	tlsCert := *tlsCertFlag
	if tlsCert == "" {
		tlsCert = os.Getenv("PHONELINK_TLS_CERT")
	}
	tlsKey := *tlsKeyFlag
	if tlsKey == "" {
		tlsKey = os.Getenv("PHONELINK_TLS_KEY")
	}
	if (tlsCert == "") != (tlsKey == "") {
		fmt.Fprintln(os.Stderr, "TLS configuration error: both --tls-cert and --tls-key must be set together")
		os.Exit(1)
	}
	if tlsCert != "" && tlsKey != "" {
		cfg.TLSCertFile = tlsCert
		cfg.TLSKeyFile = tlsKey
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	srv, err := server.NewServerWithError(cfg, logger)
	if err != nil {
		logger.Error("Failed to initialize VPS relay", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown channel
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server start error", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info(fmt.Sprintf("%s started on %s:%d", server.Name, cfg.Host, cfg.Port),
		"tls_enabled", cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",
		"persistent_state", cfg.StateFile != "",
	)

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
