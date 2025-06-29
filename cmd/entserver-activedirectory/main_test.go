package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	entserver_activedirectory "github.com/traefik/traefik/v2/cmd/entserver-activedirectory/internal"
)

func TestEntitlementService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise in tests

	cache := entserver_activedirectory.NewEntitlementCache(100, time.Minute)
	adClient := entserver_activedirectory.NewMockActiveDirectoryClient(logger)

	service := &entitlementService{
		ctx:          context.Background(),
		cache:        cache,
		adClient:     adClient,
		logger:       logger,
		cacheEnabled: true,
	}

	t.Run("Valid entitlement request", func(t *testing.T) {
		req := &EntitlementRequest{
			UserID: "alice",
			EonID:  "EON-123456",
			Env:    "production",
			Action: "read",
		}

		resp, err := service.Entitled(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp.Entitled)
		assert.Equal(t, "Access granted", resp.Message)
	})

	t.Run("Denied entitlement request", func(t *testing.T) {
		req := &EntitlementRequest{
			UserID: "alice",
			EonID:  "EON-123456",
			Env:    "production",
			Action: "admin",
		}

		resp, err := service.Entitled(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp.Entitled)
		assert.Equal(t, "Access denied", resp.Message)
	})

	t.Run("Non-existent user", func(t *testing.T) {
		req := &EntitlementRequest{
			UserID: "nonexistent",
			EonID:  "EON-123456",
			Env:    "production",
			Action: "read",
		}

		resp, err := service.Entitled(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp.Entitled)
		assert.Equal(t, "Access denied", resp.Message)
	})

	t.Run("Cache behavior", func(t *testing.T) {
		req := &EntitlementRequest{
			UserID: "bob",
			EonID:  "EON-123456",
			Env:    "production",
			Action: "write",
		}

		// First call - should hit the AD client
		resp1, err := service.Entitled(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp1.Entitled)

		// Second call - should hit the cache
		resp2, err := service.Entitled(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp2.Entitled)
		assert.Equal(t, resp1.Message, resp2.Message)

		// Verify cache was used by checking stats
		stats := cache.Stats()
		assert.True(t, stats.Hits > 0)
	})

	t.Run("Cache disabled", func(t *testing.T) {
		serviceNoCache := &entitlementService{
			ctx:          context.Background(),
			cache:        nil,
			adClient:     adClient,
			logger:       logger,
			cacheEnabled: false,
		}

		req := &EntitlementRequest{
			UserID: "alice",
			EonID:  "EON-123456",
			Env:    "production",
			Action: "read",
		}

		resp, err := serviceNoCache.Entitled(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp.Entitled)
	})
}

func TestHTTPHandlers(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cache := entserver_activedirectory.NewEntitlementCache(100, time.Minute)
	adClient := entserver_activedirectory.NewMockActiveDirectoryClient(logger)

	service := &entitlementService{
		ctx:          context.Background(),
		cache:        cache,
		adClient:     adClient,
		logger:       logger,
		cacheEnabled: true,
	}

	t.Run("HTTP entitlement endpoint - valid request", func(t *testing.T) {
		req := EntitlementRequest{
			UserID: "alice",
			EonID:  "EON-123456",
			Env:    "production",
			Action: "read",
		}

		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest("POST", "/entitlement", bytes.NewBuffer(body))
		httpReq.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		service.handleHTTPEntitlement(rr, httpReq)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp EntitlementResponse
		err := json.NewDecoder(rr.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Entitled)
		assert.Equal(t, "Access granted", resp.Message)
	})

	t.Run("HTTP entitlement endpoint - invalid method", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/entitlement", nil)
		rr := httptest.NewRecorder()

		service.handleHTTPEntitlement(rr, httpReq)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})

	t.Run("HTTP entitlement endpoint - invalid JSON", func(t *testing.T) {
		httpReq := httptest.NewRequest("POST", "/entitlement", bytes.NewBufferString("invalid json"))
		httpReq.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		service.handleHTTPEntitlement(rr, httpReq)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Health endpoint", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/health", nil)
		rr := httptest.NewRecorder()

		service.handleHealth(rr, httpReq)

		assert.Equal(t, http.StatusOK, rr.Code)

		var health map[string]interface{}
		err := json.NewDecoder(rr.Body).Decode(&health)
		require.NoError(t, err)

		assert.Equal(t, "healthy", health["status"])
		assert.Equal(t, "entserver-activedirectory", health["service"])
		assert.NotNil(t, health["timestamp"])
		assert.NotNil(t, health["cache"])

		cacheInfo := health["cache"].(map[string]interface{})
		assert.Equal(t, true, cacheInfo["enabled"])
		assert.NotNil(t, cacheInfo["stats"])
	})
}

func TestGetEntitlementMessage(t *testing.T) {
	assert.Equal(t, "Access granted", getEntitlementMessage(true))
	assert.Equal(t, "Access denied", getEntitlementMessage(false))
}

func TestParseFlags(t *testing.T) {
	// Save original args
	originalArgs := os.Args

	t.Run("Default values", func(t *testing.T) {
		os.Args = []string{"program"}
		options := parseFlags()

		assert.Equal(t, 21001, options.grpcPort)
		assert.Equal(t, "INFO", options.logLevel)
		assert.Equal(t, "none", options.tlsOptions.Tls)
		assert.True(t, options.cacheEnabled)
		assert.Equal(t, 5*time.Minute, options.cacheTTL)
		assert.Equal(t, 10000, options.maxCacheSize)
	})

	t.Run("Command line arguments", func(t *testing.T) {
		os.Args = []string{
			"program",
			"--grpc-port=9090",
			"--log-level=DEBUG",
			"--tls=mtls",
			"--keepalive",
			"--quick-test",
			"--no-cache",
			"--cache-ttl=10m",
			"--max-cache-size=5000",
		}

		options := parseFlags()

		assert.Equal(t, 9090, options.grpcPort)
		assert.Equal(t, "DEBUG", options.logLevel)
		assert.Equal(t, "mtls", options.tlsOptions.Tls)
		assert.True(t, options.keepalive)
		assert.True(t, options.quickTest)
		assert.False(t, options.cacheEnabled)
		assert.Equal(t, 10*time.Minute, options.cacheTTL)
		assert.Equal(t, 5000, options.maxCacheSize)
	})

	// Restore original args
	os.Args = originalArgs
}

func TestSetupLogger(t *testing.T) {
	t.Run("Valid log level", func(t *testing.T) {
		logger := setupLogger("DEBUG")
		assert.Equal(t, logrus.DebugLevel, logger.GetLevel())
	})

	t.Run("Invalid log level", func(t *testing.T) {
		logger := setupLogger("INVALID")
		assert.Equal(t, logrus.InfoLevel, logger.GetLevel())
	})

	t.Run("Case insensitive", func(t *testing.T) {
		logger := setupLogger("debug")
		assert.Equal(t, logrus.DebugLevel, logger.GetLevel())
	})
}

func BenchmarkEntitlementService(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cache := entserver_activedirectory.NewEntitlementCache(1000, time.Hour)
	adClient := entserver_activedirectory.NewMockActiveDirectoryClient(logger)

	service := &entitlementService{
		ctx:          context.Background(),
		cache:        cache,
		adClient:     adClient,
		logger:       logger,
		cacheEnabled: true,
	}

	req := &EntitlementRequest{
		UserID: "alice",
		EonID:  "EON-123456",
		Env:    "production",
		Action: "read",
	}

	b.Run("With cache", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			service.Entitled(context.Background(), req)
		}
	})

	serviceNoCache := &entitlementService{
		ctx:          context.Background(),
		cache:        nil,
		adClient:     adClient,
		logger:       logger,
		cacheEnabled: false,
	}

	b.Run("Without cache", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			serviceNoCache.Entitled(context.Background(), req)
		}
	})
}
