package gateway

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// maxCachedChecks bounds the access cache's memory.
const maxCachedChecks = 100_000

// accessCache reuses session checks for a short time (default 30 s):
// revoking access takes effect within it.
type accessCache struct {
	ttl time.Duration
	now func() time.Time

	mu sync.Mutex
	m  map[[32]byte]cachedCheck
}

type cachedCheck struct {
	res     checked
	expires time.Time
}

func newAccessCache(ttl time.Duration) *accessCache {
	return &accessCache{ttl: ttl, now: time.Now, m: map[[32]byte]cachedCheck{}}
}

func cacheKey(token, host string) [32]byte {
	return sha256.Sum256([]byte(token + "\x00" + host))
}

// get returns the cached decision or asks check. Only "ok" and "denied"
// are cached; an invalid session is asked about again.
func (c *accessCache) get(ctx context.Context, token, host string, check func(context.Context, string, string) (checked, error)) (checked, bool, error) {
	key := cacheKey(token, host)
	now := c.now()
	c.mu.Lock()
	if e, ok := c.m[key]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.res, true, nil
	}
	c.mu.Unlock()
	res, err := check(ctx, token, host)
	if err != nil {
		return checked{}, false, err
	}
	if c.ttl > 0 && (res.Status == "ok" || res.Status == "denied") {
		c.mu.Lock()
		if len(c.m) >= maxCachedChecks {
			for k, e := range c.m {
				if !now.Before(e.expires) {
					delete(c.m, k)
				}
			}
			if len(c.m) >= maxCachedChecks {
				// Still full of live entries: start over rather than grow
				// without bound (they are only a cache).
				clear(c.m)
			}
		}
		c.m[key] = cachedCheck{res: res, expires: now.Add(c.ttl)}
		c.mu.Unlock()
	}
	return res, false, nil
}

func (c *accessCache) forget(token, host string) {
	c.mu.Lock()
	delete(c.m, cacheKey(token, host))
	c.mu.Unlock()
}
