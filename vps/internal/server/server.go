package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

const (
	Version = "1.0.0"
	Name    = "PhoneLink VPS Relay"
)

// Config encapsulates server configuration
type Config struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

// DefaultConfig returns hardened production-ready defaults
func DefaultConfig() Config {
	return Config{
		Host:         "0.0.0.0",
		Port:         8443,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Server represents the VPS relay HTTP/WebSocket server
type Server struct {
	cfg        Config
	httpServer *http.Server
	mux        *http.ServeMux
	logger     *slog.Logger
	startTime  time.Time
}

// HealthResponse represents health check status
type HealthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Version   string `json:"version"`
	UptimeSec int64  `json:"uptime_sec"`
	Timestamp int64  `json:"timestamp"`
}

// NewServer initializes a new Server instance
func NewServer(cfg Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	mux := http.NewServeMux()
	s := &Server{
		cfg:       cfg,
		mux:       mux,
		logger:    logger,
		startTime: time.Now(),
	}

	s.registerRoutes()

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	return s
}

// registerRoutes configures all HTTP and WebSocket endpoints
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /version", s.handleVersion)
	s.mux.HandleFunc("GET /ws/v1/connect", s.handleWebSocketConnect)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:    "OK",
		Service:   Name,
		Version:   Version,
		UptimeSec: int64(time.Since(s.startTime).Seconds()),
		Timestamp: time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "%s v%s\n", Name, Version)
}

func (s *Server) handleWebSocketConnect(w http.ResponseWriter, r *http.Request) {
	// WebSocket connection handler — handshake placeholder for VPS-2/3
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "PhoneLink WebSocket Relay Endpoint Ready",
		"version": Version,
	})
}

// Handler returns the underlying http.Handler for testing
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Start runs the HTTP server listening on the configured address
func (s *Server) Start() error {
	s.logger.Info("Starting PhoneLink VPS Relay",
		"addr", s.httpServer.Addr,
		"version", Version,
	)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down PhoneLink VPS Relay")
	return s.httpServer.Shutdown(ctx)
}
