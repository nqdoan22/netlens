package dnscache

import (
	"net/netip"
	"testing"
	"time"
)

func TestLookup(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	phone := netip.MustParseAddr("192.168.137.45")
	laptop := netip.MustParseAddr("192.168.137.60")
	ip := netip.MustParseAddr("203.0.113.10")

	c := New()
	c.Add(now, phone, "a.example.com", ip, 10*time.Second)
	c.Add(now, laptop, "b.example.com", ip, 10*time.Second) // shared CDN address

	if name, _ := c.Lookup(now, phone, ip); name != "a.example.com" {
		t.Errorf("phone sees %q, want its own lookup", name)
	}
	if name, _ := c.Lookup(now, laptop, ip); name != "b.example.com" {
		t.Errorf("laptop sees %q, want its own lookup", name)
	}
	other := netip.MustParseAddr("192.168.137.99")
	if _, ok := c.Lookup(now, other, ip); !ok {
		t.Error("no global fallback for a device that did not do the lookup")
	}
	// Short TTLs are stretched to MinTTL so the following connection is labeled.
	if _, ok := c.Lookup(now.Add(MinTTL-time.Second), phone, ip); !ok {
		t.Error("entry expired before MinTTL")
	}
	if _, ok := c.Lookup(now.Add(MinTTL), phone, ip); ok {
		t.Error("entry still valid after MinTTL")
	}
}
