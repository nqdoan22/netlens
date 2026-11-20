// Package device keeps track of the local devices (phones, laptops, ...) seen on
// the monitored network, keyed by their IP address.
package device

import (
	"net"
	"net/netip"
	"time"
)

// Device is a local host observed on the monitored network.
type Device struct {
	IP        netip.Addr
	MAC       string
	Hostname  string // learned from DHCP, may be empty
	FirstSeen time.Time
	LastSeen  time.Time
}

// Label returns a human-friendly name: the hostname if known, else the IP.
func (d *Device) Label() string {
	if d.Hostname != "" {
		return d.Hostname
	}
	return d.IP.String()
}

// Registry stores devices. It is not safe for concurrent use.
type Registry struct {
	byIP      map[netip.Addr]*Device
	hostByMAC map[string]string // hostnames learned from DHCP before the IP is known
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byIP: make(map[netip.Addr]*Device), hostByMAC: make(map[string]string)}
}

// IsLocal reports whether addr belongs to a device on the local network rather
// than to a server on the Internet.
func IsLocal(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback()
}

// Observe records that a local device with this IP (and MAC, if known) was seen.
// It returns the device and whether it is new.
func (r *Registry) Observe(now time.Time, ip netip.Addr, mac net.HardwareAddr) (*Device, bool) {
	d, ok := r.byIP[ip]
	if !ok {
		d = &Device{IP: ip, FirstSeen: now}
		r.byIP[ip] = d
	}
	d.LastSeen = now
	if len(mac) > 0 && d.MAC == "" {
		d.MAC = mac.String()
	}
	if d.Hostname == "" && d.MAC != "" {
		d.Hostname = r.hostByMAC[d.MAC]
	}
	return d, !ok
}

// Get returns the device with this IP, if known.
func (r *Registry) Get(ip netip.Addr) (*Device, bool) {
	d, ok := r.byIP[ip]
	return d, ok
}

// LearnHostname associates a DHCP hostname with a MAC address and, when known,
// the IP the device was assigned.
func (r *Registry) LearnHostname(now time.Time, mac net.HardwareAddr, ip netip.Addr, hostname string) {
	if hostname == "" || len(mac) == 0 {
		return
	}
	m := mac.String()
	r.hostByMAC[m] = hostname
	if ip.IsValid() {
		d, _ := r.Observe(now, ip, mac)
		d.Hostname = hostname
		return
	}
	for _, d := range r.byIP {
		if d.MAC == m {
			d.Hostname = hostname
		}
	}
}

// All returns every known device.
func (r *Registry) All() []*Device {
	out := make([]*Device, 0, len(r.byIP))
	for _, d := range r.byIP {
		out = append(out, d)
	}
	return out
}
