package internal

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// ActiveDirectoryClient interface for entitlement checking
type ActiveDirectoryClient interface {
	CheckEntitlement(ctx context.Context, userID, eonID, env, action string) (bool, error)
}

// MockActiveDirectoryClient provides a mock implementation for testing
type MockActiveDirectoryClient struct {
	logger *logrus.Logger
	users  map[string]map[string]bool
}

// NewActiveDirectoryClient creates a new Active Directory client
func NewActiveDirectoryClient(logger *logrus.Logger) ActiveDirectoryClient {
	// For now, return a mock implementation
	// In a real implementation, this would connect to actual AD services
	return NewMockActiveDirectoryClient(logger)
}

// NewMockActiveDirectoryClient creates a new mock Active Directory client
func NewMockActiveDirectoryClient(logger *logrus.Logger) *MockActiveDirectoryClient {
	// Mock user database with predefined permissions
	users := map[string]map[string]bool{
		"alice": {
			"EON-123456:production:read":   true,
			"EON-123456:production:write":  false,
			"EON-123456:production:admin":  false,
			"EON-123456:development:read":  true,
			"EON-123456:development:write": true,
			"EON-123456:development:admin": false,
		},
		"bob": {
			"EON-123456:production:read":   true,
			"EON-123456:production:write":  true,
			"EON-123456:production:admin":  false,
			"EON-123456:development:read":  true,
			"EON-123456:development:write": true,
			"EON-123456:development:admin": true,
		},
		"admin": {
			"EON-123456:production:read":   true,
			"EON-123456:production:write":  true,
			"EON-123456:production:admin":  true,
			"EON-123456:development:read":  true,
			"EON-123456:development:write": true,
			"EON-123456:development:admin": true,
		},
		"carol": {
			"EON-789012:production:read":   true,
			"EON-789012:production:write":  false,
			"EON-789012:production:admin":  false,
		},
		"dave": {
			"EON-345678:development:read":  true,
			"EON-345678:development:write": true,
			"EON-345678:development:admin": false,
		},
	}

	return &MockActiveDirectoryClient{
		logger: logger,
		users:  users,
	}
}

// CheckEntitlement checks if a user is entitled to perform an action
func (m *MockActiveDirectoryClient) CheckEntitlement(ctx context.Context, userID, eonID, env, action string) (bool, error) {
	logger := m.logger.WithFields(logrus.Fields{
		"userID": userID,
		"eonID":  eonID,
		"env":    env,
		"action": action,
	})

	logger.Debug("Checking entitlement")

	// Normalize userID (remove domain prefix if present)
	if strings.Contains(userID, "\\") {
		parts := strings.Split(userID, "\\")
		userID = parts[len(parts)-1]
	}
	userID = strings.ToLower(userID)

	// Get user permissions
	userPerms, userExists := m.users[userID]
	if !userExists {
		logger.Debug("User not found in permissions database")
		return false, nil
	}

	// Create permission key
	permissionKey := fmt.Sprintf("%s:%s:%s", eonID, env, action)
	entitled, hasPermission := userPerms[permissionKey]

	if !hasPermission {
		logger.Debug("Permission not defined for user")
		return false, nil
	}

	logger.WithField("entitled", entitled).Debug("Entitlement check completed")
	return entitled, nil
}

// AddUserPermission adds a permission for a user (useful for testing)
func (m *MockActiveDirectoryClient) AddUserPermission(userID, eonID, env, action string, entitled bool) {
	userID = strings.ToLower(userID)
	if m.users[userID] == nil {
		m.users[userID] = make(map[string]bool)
	}
	
	permissionKey := fmt.Sprintf("%s:%s:%s", eonID, env, action)
	m.users[userID][permissionKey] = entitled
	
	m.logger.WithFields(logrus.Fields{
		"userID":    userID,
		"eonID":     eonID,
		"env":       env,
		"action":    action,
		"entitled":  entitled,
	}).Debug("User permission added")
}

// RemoveUserPermission removes a permission for a user
func (m *MockActiveDirectoryClient) RemoveUserPermission(userID, eonID, env, action string) {
	userID = strings.ToLower(userID)
	if m.users[userID] == nil {
		return
	}
	
	permissionKey := fmt.Sprintf("%s:%s:%s", eonID, env, action)
	delete(m.users[userID], permissionKey)
	
	m.logger.WithFields(logrus.Fields{
		"userID": userID,
		"eonID":  eonID,
		"env":    env,
		"action": action,
	}).Debug("User permission removed")
}

// ListUserPermissions returns all permissions for a user
func (m *MockActiveDirectoryClient) ListUserPermissions(userID string) map[string]bool {
	userID = strings.ToLower(userID)
	if m.users[userID] == nil {
		return make(map[string]bool)
	}
	
	// Return a copy to prevent external modification
	permissions := make(map[string]bool)
	for key, value := range m.users[userID] {
		permissions[key] = value
	}
	
	return permissions
}
