package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	entserver_activedirectory "github.com/traefik/traefik/v2/cmd/entserver-activedirectory/internal"
)

type entitlementOptions struct {
	grpcPort     int
	logLevel     string
	tlsOptions   entserver_activedirectory.TlsOptions
	keepalive    bool
	quickTest    bool
	cacheEnabled bool
	cacheTTL     time.Duration
	maxCacheSize int
}

type entitlementService struct {
	ctx         context.Context
	cache       *entserver_activedirectory.EntitlementCache
	adClient    entserver_activedirectory.ActiveDirectoryClient
	logger      *logrus.Logger
	cacheEnabled bool
}

// EntitlementRequest represents the incoming entitlement request
type EntitlementRequest struct {
	UserID string `json:"userID"`
	EonID  string `json:"eonID"`
	Env    string `json:"env"`
	Action string `json:"action"`
}

// EntitlementResponse represents the entitlement response
type EntitlementResponse struct {
	Entitled bool   `json:"entitled"`
	Message  string `json:"message,omitempty"`
}

func parseFlags() entitlementOptions {
	options := entitlementOptions{
		grpcPort:     21001,
		logLevel:     "INFO",
		keepalive:    false,
		quickTest:    false,
		cacheEnabled: true,
		cacheTTL:     5 * time.Minute,
		maxCacheSize: 10000,
		tlsOptions: entserver_activedirectory.TlsOptions{
			Tls:     "none",
			Cert:    "cert.pem",
			Key:     "key.pem",
			Cacert:  "cacert.pem",
			AllowedUsers: "",
		},
	}

	// Parse command line arguments (simplified version)
	for i, arg := range os.Args[1:] {
		switch {
		case strings.HasPrefix(arg, "--grpc-port="):
			if port, err := strconv.Atoi(strings.TrimPrefix(arg, "--grpc-port=")); err == nil {
				options.grpcPort = port
			}
		case strings.HasPrefix(arg, "--log-level="):
			options.logLevel = strings.TrimPrefix(arg, "--log-level=")
		case strings.HasPrefix(arg, "--tls="):
			options.tlsOptions.Tls = strings.TrimPrefix(arg, "--tls=")
		case strings.HasPrefix(arg, "--cert="):
			options.tlsOptions.Cert = strings.TrimPrefix(arg, "--cert=")
		case strings.HasPrefix(arg, "--key="):
			options.tlsOptions.Key = strings.TrimPrefix(arg, "--key=")
		case strings.HasPrefix(arg, "--cacert="):
			options.tlsOptions.Cacert = strings.TrimPrefix(arg, "--cacert=")
		case strings.HasPrefix(arg, "--allowed-users="):
			options.tlsOptions.AllowedUsers = strings.TrimPrefix(arg, "--allowed-users=")
		case arg == "--keepalive":
			options.keepalive = true
		case arg == "--quick-test":
			options.quickTest = true
		case arg == "--no-cache":
			options.cacheEnabled = false
		case strings.HasPrefix(arg, "--cache-ttl="):
			if ttl, err := time.ParseDuration(strings.TrimPrefix(arg, "--cache-ttl=")); err == nil {
				options.cacheTTL = ttl
			}
		case strings.HasPrefix(arg, "--max-cache-size="):
			if size, err := strconv.Atoi(strings.TrimPrefix(arg, "--max-cache-size=")); err == nil {
				options.maxCacheSize = size
			}
		}
		_ = i // Suppress unused variable warning
	}

	// Override with environment variables
	if port := os.Getenv("GRPC_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			options.grpcPort = p
		}
	}
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		options.logLevel = level
	}
	if tls := os.Getenv("TLS_OPTIONS_TLS"); tls != "" {
		options.tlsOptions.Tls = tls
	}
	if cert := os.Getenv("TLS_OPTIONS_CERT"); cert != "" {
		options.tlsOptions.Cert = cert
	}
	if key := os.Getenv("TLS_OPTIONS_KEY"); key != "" {
		options.tlsOptions.Key = key
	}
	if cacert := os.Getenv("TLS_OPTIONS_CACERT"); cacert != "" {
		options.tlsOptions.Cacert = cacert
	}
	if users := os.Getenv("TLS_OPTIONS_ALLOWED_USERS"); users != "" {
		options.tlsOptions.AllowedUsers = users
	}
	if keepalive := os.Getenv("KEEPALIVE"); keepalive == "true" {
		options.keepalive = true
	}
	if quickTest := os.Getenv("QUICK_TEST"); quickTest == "true" {
		options.quickTest = true
	}
	if cache := os.Getenv("CACHE_ENABLED"); cache == "false" {
		options.cacheEnabled = false
	}
	if ttl := os.Getenv("CACHE_TTL"); ttl != "" {
		if duration, err := time.ParseDuration(ttl); err == nil {
			options.cacheTTL = duration
		}
	}
	if maxSize := os.Getenv("MAX_CACHE_SIZE"); maxSize != "" {
		if size, err := strconv.Atoi(maxSize); err == nil {
			options.maxCacheSize = size
		}
	}

	return options
}

func setupLogger(level string) *logrus.Logger {
	logger := logrus.New()
	
	// Add timestamp
	customFormatter := new(logrus.TextFormatter)
	customFormatter.FullTimestamp = true
	logger.SetFormatter(customFormatter)

	// Set log level
	if parsedLevel, err := logrus.ParseLevel(strings.ToLower(level)); err == nil {
		logger.SetLevel(parsedLevel)
	} else {
		logger.Warnf("Invalid log level '%s', defaulting to INFO", level)
		logger.SetLevel(logrus.InfoLevel)
	}

	return logger
}

func (ent *entitlementService) Entitled(ctx context.Context, req *EntitlementRequest) (*EntitlementResponse, error) {
	logger := ent.logger.WithFields(logrus.Fields{
		"userID": req.UserID,
		"eonID":  req.EonID,
		"env":    req.Env,
		"action": req.Action,
	})

	logger.Debug("Processing entitlement request")

	// Create cache key
	cacheKey := fmt.Sprintf("%s:%s:%s:%s", req.UserID, req.EonID, req.Env, req.Action)

	// Check cache first if enabled
	if ent.cacheEnabled && ent.cache != nil {
		if cached, found := ent.cache.Get(cacheKey); found {
			logger.Debug("Entitlement found in cache")
			return &EntitlementResponse{
				Entitled: cached,
				Message:  getEntitlementMessage(cached),
			}, nil
		}
	}

	// Perform actual entitlement check
	entitled, err := ent.adClient.CheckEntitlement(ctx, req.UserID, req.EonID, req.Env, req.Action)
	if err != nil {
		logger.WithError(err).Error("Failed to check entitlement")
		return nil, fmt.Errorf("entitlement check failed: %w", err)
	}

	// Cache the result if cache is enabled
	if ent.cacheEnabled && ent.cache != nil {
		ent.cache.Set(cacheKey, entitled)
		logger.Debug("Entitlement result cached")
	}

	response := &EntitlementResponse{
		Entitled: entitled,
		Message:  getEntitlementMessage(entitled),
	}

	logger.WithField("entitled", entitled).Info("Entitlement check completed")
	return response, nil
}

func getEntitlementMessage(entitled bool) string {
	if entitled {
		return "Access granted"
	}
	return "Access denied"
}

func (ent *entitlementService) handleHTTPEntitlement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EntitlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ent.logger.WithError(err).Error("Failed to decode entitlement request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	response, err := ent.Entitled(r.Context(), &req)
	if err != nil {
		ent.logger.WithError(err).Error("Entitlement check failed")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		ent.logger.WithError(err).Error("Failed to encode response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (ent *entitlementService) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"service":   "entserver-activedirectory",
		"timestamp": time.Now().Unix(),
		"cache": map[string]interface{}{
			"enabled": ent.cacheEnabled,
		},
	}

	if ent.cacheEnabled && ent.cache != nil {
		stats := ent.cache.Stats()
		health["cache"].(map[string]interface{})["stats"] = stats
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func main() {
	options := parseFlags()
	logger := setupLogger(options.logLevel)

	logger.Info("entserver-activedirectory starting")
	logger.WithFields(logrus.Fields{
		"grpcPort":     options.grpcPort,
		"logLevel":     options.logLevel,
		"cacheEnabled": options.cacheEnabled,
		"cacheTTL":     options.cacheTTL,
		"maxCacheSize": options.maxCacheSize,
	}).Info("Configuration loaded")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize cache if enabled
	var cache *entserver_activedirectory.EntitlementCache
	if options.cacheEnabled {
		cache = entserver_activedirectory.NewEntitlementCache(options.maxCacheSize, options.cacheTTL)
		logger.Info("Entitlement cache initialized")
	}

	// Initialize Active Directory client
	adClient := entserver_activedirectory.NewActiveDirectoryClient(logger)

	// Quick test mode
	if options.quickTest {
		logger.Info("Running in quick test mode")
		if err := runQuickTest(ctx, logger, adClient, cache); err != nil {
			logger.WithError(err).Fatal("Quick test failed")
		}
		return
	}

	// Create entitlement service
	service := &entitlementService{
		ctx:          ctx,
		cache:        cache,
		adClient:     adClient,
		logger:       logger,
		cacheEnabled: options.cacheEnabled,
	}

	// Setup HTTP server for REST API
	mux := http.NewServeMux()
	mux.HandleFunc("/entitlement", service.handleHTTPEntitlement)
	mux.HandleFunc("/health", service.handleHealth)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", options.grpcPort+1000), // HTTP on grpcPort + 1000
		Handler: mux,
	}

	// Setup gRPC server for compatibility
	var serverOptions []grpc.ServerOption
	if options.keepalive {
		kaPolicy := keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}
		serverOptions = append(serverOptions, grpc.KeepaliveEnforcementPolicy(kaPolicy))
	}

	// Handle TLS configuration
	switch options.tlsOptions.Tls {
	case "oneway":
		logger.Info("TLS oneway mode not yet implemented")
	case "mtls":
		logger.Info("TLS mtls mode not yet implemented")
	default:
		logger.Info("Running without TLS")
	}

	grpcServer := grpc.NewServer(serverOptions...)

	// Start gRPC server
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", options.grpcPort))
	if err != nil {
		logger.WithError(err).Fatal("Failed to listen on gRPC port")
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("HTTP server starting on port %d", options.grpcPort+1000)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Error("HTTP server error")
		}
	}()

	// Start gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("gRPC server starting on port %d", options.grpcPort)
		if err := grpcServer.Serve(listener); err != nil {
			logger.WithError(err).Error("gRPC server error")
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutting down gracefully...")

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 10*time.Second)
	defer shutdownCancel()
	
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("HTTP server shutdown error")
	}

	// Shutdown gRPC server
	grpcServer.GracefulStop()

	// Wait for all goroutines to finish
	wg.Wait()
	logger.Info("Server shutdown complete")
}

func runQuickTest(ctx context.Context, logger *logrus.Logger, adClient entserver_activedirectory.ActiveDirectoryClient, cache *entserver_activedirectory.EntitlementCache) error {
	logger.Info("Running quick test...")

	testCases := []struct {
		userID   string
		eonID    string
		env      string
		action   string
		expected bool
	}{
		{"alice", "EON-123456", "production", "read", true},
		{"bob", "EON-123456", "production", "write", true},
		{"admin", "EON-123456", "production", "admin", true},
		{"unauthorized", "EON-123456", "production", "read", false},
	}

	for _, tc := range testCases {
		logger.Infof("Testing user=%s, eonID=%s, env=%s, action=%s", tc.userID, tc.eonID, tc.env, tc.action)
		
		entitled, err := adClient.CheckEntitlement(ctx, tc.userID, tc.eonID, tc.env, tc.action)
		if err != nil {
			return fmt.Errorf("entitlement check failed for %s: %w", tc.userID, err)
		}

		if entitled != tc.expected {
			return fmt.Errorf("unexpected entitlement result for %s: got %t, expected %t", tc.userID, entitled, tc.expected)
		}

		logger.Infof("✓ Test passed for user %s", tc.userID)
	}

	if cache != nil {
		logger.Info("Testing cache functionality...")
		cacheKey := "test:cache:key"
		cache.Set(cacheKey, true)
		
		if value, found := cache.Get(cacheKey); !found || !value {
			return fmt.Errorf("cache test failed")
		}
		
		logger.Info("✓ Cache test passed")
	}

	logger.Info("All quick tests passed!")
	return nil
}
