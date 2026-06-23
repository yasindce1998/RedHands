package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

type entry struct {
	result    *mcp.ToolResult
	expiresAt time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]*entry
	maxSize int
	ttl     time.Duration
}

func New(maxSize int, ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]*entry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *Cache) Get(key string) (*mcp.ToolResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.result, true
}

func (c *Cache) Set(key string, result *mcp.ToolResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evict()
	}

	c.entries[key] = &entry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *Cache) evict() {
	var oldest string
	var oldestTime time.Time

	for k, e := range c.entries {
		if time.Now().After(e.expiresAt) {
			delete(c.entries, k)
			return
		}
		if oldest == "" || e.expiresAt.Before(oldestTime) {
			oldest = k
			oldestTime = e.expiresAt
		}
	}
	if oldest != "" {
		delete(c.entries, oldest)
	}
}

func MakeKey(toolName string, params json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(toolName))
	h.Write([]byte(":"))
	h.Write(params)
	return hex.EncodeToString(h.Sum(nil))
}

func Middleware(c *Cache) mcp.Middleware {
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, toolName string, params json.RawMessage) (*mcp.ToolResult, error) {
			key := MakeKey(toolName, params)

			if result, ok := c.Get(key); ok {
				return result, nil
			}

			result, err := next(ctx, toolName, params)
			if err == nil && result != nil && !result.IsError {
				c.Set(key, result)
			}
			return result, err
		}
	}
}
