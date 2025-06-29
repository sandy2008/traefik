package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go/ext"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/middlewares/accesslog"
	"github.com/traefik/traefik/v2/pkg/tracing"
)

const (
	typeName = "ActiveDirectoryAuth"
)

// ActiveDirectoryAuth holds the Active Directory authentication configuration.
type activeDirectoryAuth struct {
	next            http.Handler
	name            string
	serverURL       string
	eonID           string
	env             string
	action          string
	userIDHeader    string
	removeHeader    bool
	timeoutDuration time.Duration
}

// EntitlementRequest represents the request sent to entserver-activedirectory.
type EntitlementRequest struct {
	UserID string `json:"userID"`
	EonID  string `json:"eonID"`
	Env    string `json:"env"`
	Action string `json:"action"`
}

// EntitlementResponse represents the response from entserver-activedirectory.
type EntitlementResponse struct {
	Entitled bool   `json:"entitled"`
	Message  string `json:"message,omitempty"`
}

// New creates a new Active Directory authentication middleware.
func New(ctx context.Context, next http.Handler, config dynamic.ActiveDirectoryAuth, name string) (http.Handler, error) {
	logger := log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName))
	logger.Debug("Creating middleware")

	if config.ServerURL == "" {
		return nil, fmt.Errorf("serverURL is required for Active Directory authentication")
	}

	if config.EonID == "" {
		return nil, fmt.Errorf("eonID is required for Active Directory authentication")
	}

	if config.Env == "" {
		return nil, fmt.Errorf("env is required for Active Directory authentication")
	}

	if config.Action == "" {
		return nil, fmt.Errorf("action is required for Active Directory authentication")
	}

	userIDHeader := config.UserIDHeader
	if userIDHeader == "" {
		userIDHeader = "X-User-ID"
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &activeDirectoryAuth{
		next:            next,
		name:            name,
		serverURL:       config.ServerURL,
		eonID:           config.EonID,
		env:             config.Env,
		action:          config.Action,
		userIDHeader:    userIDHeader,
		removeHeader:    config.RemoveHeader,
		timeoutDuration: timeout,
	}, nil
}

func (a *activeDirectoryAuth) GetTracingInformation() (string, ext.SpanKindEnum) {
	return a.name, tracing.SpanKindNoneEnum
}

func (a *activeDirectoryAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := log.FromContext(middlewares.GetLoggerCtx(req.Context(), a.name, typeName))

	// Extract UserID from header
	userID := req.Header.Get(a.userIDHeader)
	if userID == "" {
		logger.Debug("UserID header not found")
		http.Error(rw, "UserID header is required", http.StatusUnauthorized)
		return
	}

	// Strip any domain prefix if present (e.g., "domain\user" -> "user")
	if strings.Contains(userID, "\\") {
		parts := strings.Split(userID, "\\")
		userID = parts[len(parts)-1]
	}

	logger.Debugf("Checking entitlement for user: %s", userID)

	// Check entitlement with entserver-activedirectory
	entitled, err := a.checkEntitlement(req.Context(), userID)
	if err != nil {
		logger.Errorf("Failed to check entitlement: %v", err)
		tracing.SetErrorWithEvent(req, "Failed to check entitlement")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set access log data
	logData := accesslog.GetLogData(req)
	if logData != nil {
		logData.Core[accesslog.ClientUsername] = userID
	}

	if !entitled {
		logger.Debugf("Access denied for user: %s", userID)
		tracing.SetErrorWithEvent(req, "Access denied")
		http.Error(rw, "Access denied", http.StatusForbidden)
		return
	}

	logger.Debugf("Access granted for user: %s", userID)

	// Remove the UserID header if configured to do so
	if a.removeHeader {
		logger.Debug("Removing UserID header")
		req.Header.Del(a.userIDHeader)
	}

	// Continue to next handler
	a.next.ServeHTTP(rw, req)
}

func (a *activeDirectoryAuth) checkEntitlement(ctx context.Context, userID string) (bool, error) {
	// Create entitlement request
	entRequest := EntitlementRequest{
		UserID: userID,
		EonID:  a.eonID,
		Env:    a.env,
		Action: a.action,
	}

	// Marshal request to JSON
	requestBody, err := json.Marshal(entRequest)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request with timeout
	ctx, cancel := context.WithTimeout(ctx, a.timeoutDuration)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", a.serverURL+"/entitlement", bytes.NewBuffer(requestBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("entserver returned status: %d", resp.StatusCode)
	}

	// Parse response
	var entResponse EntitlementResponse
	if err := json.NewDecoder(resp.Body).Decode(&entResponse); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	return entResponse.Entitled, nil
}
