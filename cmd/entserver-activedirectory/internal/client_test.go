package internal

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntitlementCache(t *testing.T) {
	cache := NewEntitlementCache(10, 100*time.Millisecond)

	t.Run("Set and Get", func(t *testing.T) {
		cache.Set("test:key", true)
		
		value, found := cache.Get("test:key")
		assert.True(t, found)
		assert.True(t, value)
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		_, found := cache.Get("non:existent")
		assert.False(t, found)
	})

	t.Run("Expiration", func(t *testing.T) {
		cache.Set("expire:key", false)
		
		// Should be found immediately
		value, found := cache.Get("expire:key")
		assert.True(t, found)
		assert.False(t, value)
		
		// Wait for expiration
		time.Sleep(150 * time.Millisecond)
		
		// Should be expired
		_, found = cache.Get("expire:key")
		assert.False(t, found)
	})

	t.Run("Cache stats", func(t *testing.T) {
		cache.Clear()
		
		// Generate some hits and misses
		cache.Set("stats:key", true)
		cache.Get("stats:key")    // hit
		cache.Get("stats:missing") // miss
		
		stats := cache.Stats()
		assert.Equal(t, 1, stats.Size)
		assert.Equal(t, 10, stats.MaxSize)
		assert.True(t, stats.Hits > 0)
		assert.True(t, stats.Misses > 0)
	})

	t.Run("Max size eviction", func(t *testing.T) {
		smallCache := NewEntitlementCache(2, time.Hour)
		
		smallCache.Set("key1", true)
		smallCache.Set("key2", false)
		smallCache.Set("key3", true) // Should evict key1
		
		_, found1 := smallCache.Get("key1")
		_, found2 := smallCache.Get("key2")
		_, found3 := smallCache.Get("key3")
		
		assert.False(t, found1) // Should be evicted
		assert.True(t, found2)
		assert.True(t, found3)
		
		stats := smallCache.Stats()
		assert.Equal(t, 2, stats.Size)
		assert.True(t, stats.Evictions > 0)
	})

	t.Run("Delete", func(t *testing.T) {
		cache.Set("delete:key", true)
		
		_, found := cache.Get("delete:key")
		assert.True(t, found)
		
		cache.Delete("delete:key")
		
		_, found = cache.Get("delete:key")
		assert.False(t, found)
	})

	t.Run("Clear", func(t *testing.T) {
		cache.Set("clear:key1", true)
		cache.Set("clear:key2", false)
		
		stats := cache.Stats()
		assert.True(t, stats.Size > 0)
		
		cache.Clear()
		
		stats = cache.Stats()
		assert.Equal(t, 0, stats.Size)
	})
}

func TestMockActiveDirectoryClient(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	client := NewMockActiveDirectoryClient(logger)
	ctx := context.Background()

	t.Run("Check existing user permissions", func(t *testing.T) {
		// Alice should have read access to production
		entitled, err := client.CheckEntitlement(ctx, "alice", "EON-123456", "production", "read")
		require.NoError(t, err)
		assert.True(t, entitled)

		// Alice should not have write access to production
		entitled, err = client.CheckEntitlement(ctx, "alice", "EON-123456", "production", "write")
		require.NoError(t, err)
		assert.False(t, entitled)

		// Bob should have write access to production
		entitled, err = client.CheckEntitlement(ctx, "bob", "EON-123456", "production", "write")
		require.NoError(t, err)
		assert.True(t, entitled)

		// Admin should have admin access to production
		entitled, err = client.CheckEntitlement(ctx, "admin", "EON-123456", "production", "admin")
		require.NoError(t, err)
		assert.True(t, entitled)
	})

	t.Run("Check non-existent user", func(t *testing.T) {
		entitled, err := client.CheckEntitlement(ctx, "nonexistent", "EON-123456", "production", "read")
		require.NoError(t, err)
		assert.False(t, entitled)
	})

	t.Run("Check non-existent permission", func(t *testing.T) {
		entitled, err := client.CheckEntitlement(ctx, "alice", "EON-999999", "production", "read")
		require.NoError(t, err)
		assert.False(t, entitled)
	})

	t.Run("Domain prefix handling", func(t *testing.T) {
		// Test with domain prefix
		entitled, err := client.CheckEntitlement(ctx, "DOMAIN\\alice", "EON-123456", "production", "read")
		require.NoError(t, err)
		assert.True(t, entitled)
	})

	t.Run("Case insensitive userID", func(t *testing.T) {
		entitled, err := client.CheckEntitlement(ctx, "ALICE", "EON-123456", "production", "read")
		require.NoError(t, err)
		assert.True(t, entitled)
	})

	t.Run("Add and remove permissions", func(t *testing.T) {
		mockClient := client
		
		// Add new permission
		mockClient.AddUserPermission("testuser", "EON-TEST", "dev", "read", true)
		
		entitled, err := mockClient.CheckEntitlement(ctx, "testuser", "EON-TEST", "dev", "read")
		require.NoError(t, err)
		assert.True(t, entitled)
		
		// Remove permission
		mockClient.RemoveUserPermission("testuser", "EON-TEST", "dev", "read")
		
		entitled, err = mockClient.CheckEntitlement(ctx, "testuser", "EON-TEST", "dev", "read")
		require.NoError(t, err)
		assert.False(t, entitled)
	})

	t.Run("List user permissions", func(t *testing.T) {
		mockClient := client
		
		permissions := mockClient.ListUserPermissions("alice")
		assert.True(t, len(permissions) > 0)
		
		// Check specific permission exists
		assert.True(t, permissions["EON-123456:production:read"])
		assert.False(t, permissions["EON-123456:production:write"])
		
		// Check non-existent user
		permissions = mockClient.ListUserPermissions("nonexistent")
		assert.Equal(t, 0, len(permissions))
	})
}

func TestNewActiveDirectoryClient(t *testing.T) {
	logger := logrus.New()
	client := NewActiveDirectoryClient(logger)
	
	assert.NotNil(t, client)
	
	// Test that it returns a mock client for now
	mockClient, ok := client.(*MockActiveDirectoryClient)
	assert.True(t, ok)
	assert.NotNil(t, mockClient)
}

func BenchmarkCacheOperations(b *testing.B) {
	cache := NewEntitlementCache(1000, time.Hour)
	
	b.Run("Set", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cache.Set("bench:key", true)
		}
	})
	
	b.Run("Get", func(b *testing.B) {
		cache.Set("bench:key", true)
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			cache.Get("bench:key")
		}
	})
	
	b.Run("SetAndGet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key := "bench:key"
			cache.Set(key, true)
			cache.Get(key)
		}
	})
}

func BenchmarkEntitlementCheck(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce logging overhead
	
	client := NewMockActiveDirectoryClient(logger)
	ctx := context.Background()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		client.CheckEntitlement(ctx, "alice", "EON-123456", "production", "read")
	}
}
