package internal

import (
	"sync"
	"time"
)

// CacheItem represents a cached entitlement result
type CacheItem struct {
	Value     bool
	ExpiresAt time.Time
}

// EntitlementCache provides thread-safe caching for entitlement results
type EntitlementCache struct {
	cache    map[string]*CacheItem
	mutex    sync.RWMutex
	ttl      time.Duration
	maxSize  int
	hits     int64
	misses   int64
	evictions int64
}

// CacheStats represents cache statistics
type CacheStats struct {
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Evictions int64 `json:"evictions"`
	Size      int   `json:"size"`
	MaxSize   int   `json:"maxSize"`
}

// NewEntitlementCache creates a new entitlement cache
func NewEntitlementCache(maxSize int, ttl time.Duration) *EntitlementCache {
	cache := &EntitlementCache{
		cache:   make(map[string]*CacheItem),
		ttl:     ttl,
		maxSize: maxSize,
	}
	
	// Start cleanup goroutine
	go cache.cleanupExpired()
	
	return cache
}

// Get retrieves a value from the cache
func (c *EntitlementCache) Get(key string) (bool, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, exists := c.cache[key]
	if !exists {
		c.misses++
		return false, false
	}

	if time.Now().After(item.ExpiresAt) {
		c.misses++
		// Don't delete here to avoid deadlock, let cleanup handle it
		return false, false
	}

	c.hits++
	return item.Value, true
}

// Set stores a value in the cache
func (c *EntitlementCache) Set(key string, value bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if we need to evict items
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[key] = &CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

// Delete removes a value from the cache
func (c *EntitlementCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.cache, key)
}

// Clear removes all values from the cache
func (c *EntitlementCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache = make(map[string]*CacheItem)
}

// Stats returns cache statistics
func (c *EntitlementCache) Stats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return CacheStats{
		Hits:      c.hits,
		Misses:    c.misses,
		Evictions: c.evictions,
		Size:      len(c.cache),
		MaxSize:   c.maxSize,
	}
}

// evictOldest removes the oldest item from the cache
func (c *EntitlementCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, item := range c.cache {
		if oldestKey == "" || item.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
		c.evictions++
	}
}

// cleanupExpired removes expired items from the cache
func (c *EntitlementCache) cleanupExpired() {
	ticker := time.NewTicker(time.Minute) // Cleanup every minute
	defer ticker.Stop()

	for range ticker.C {
		c.mutex.Lock()
		now := time.Now()
		for key, item := range c.cache {
			if now.After(item.ExpiresAt) {
				delete(c.cache, key)
			}
		}
		c.mutex.Unlock()
	}
}
