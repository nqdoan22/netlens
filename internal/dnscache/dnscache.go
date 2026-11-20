// Package dnscache remembers which host name each device looked up to obtain an
// IP address, so that a later connection to that IP can be labeled with the
// name the user's app actually asked for (e.g. "graph.instagram.com" rather than
// a CDN alias or a bare IP).
package dnscache

import (
	"net/netip"
	"time"
)

const (
	// MinTTL keeps short-TTL answers around long enough to label the connection
	// that follows the lookup; clients often cache longer than the TTL anyway.
	MinTTL = 5 * time.Minute
	// MaxTTL bounds memory use for answers with very long TTLs.
	MaxTTL = 24 * time.Hour
)

type key struct {
	client netip.Addr
	server netip.Addr
}

type entry struct {
	name    string
	expires time.Time
}

// Cache maps (client, server IP) to the host name the client resolved.
// It is not safe for concurrent use.
type Cache struct {
	perClient map[key]entry
	global    map[netip.Addr]entry // fallback when the lookup came from another client
	lastSweep time.Time
}

// New returns an empty cache.
func New() *Cache {
	return &Cache{perClient: make(map[key]entry), global: make(map[netip.Addr]entry)}
}

// Add records that client resolved name to addr at time now.
func (c *Cache) Add(now time.Time, client netip.Addr, name string, addr netip.Addr, ttl time.Duration) {
	ttl = min(max(ttl, MinTTL), MaxTTL)
	e := entry{name: name, expires: now.Add(ttl)}
	c.perClient[key{client, addr}] = e
	c.global[addr] = e
	c.maybeSweep(now)
}

// Lookup returns the name client resolved for addr, if still known.
func (c *Cache) Lookup(now time.Time, client, addr netip.Addr) (string, bool) {
	if e, ok := c.perClient[key{client, addr}]; ok && now.Before(e.expires) {
		return e.name, true
	}
	if e, ok := c.global[addr]; ok && now.Before(e.expires) {
		return e.name, true
	}
	return "", false
}

// Len returns the number of per-client entries.
func (c *Cache) Len() int { return len(c.perClient) }

func (c *Cache) maybeSweep(now time.Time) {
	if now.Sub(c.lastSweep) < time.Minute {
		return
	}
	c.lastSweep = now
	for k, e := range c.perClient {
		if !now.Before(e.expires) {
			delete(c.perClient, k)
		}
	}
	for k, e := range c.global {
		if !now.Before(e.expires) {
			delete(c.global, k)
		}
	}
}
