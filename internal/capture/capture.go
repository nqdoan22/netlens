// Package capture provides packet sources: live capture from a network
// interface (Npcap on Windows, AF_PACKET on Linux) and replay of pcap/pcapng files.
package capture

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Source yields captured frames.
type Source interface {
	// ReadPacket returns the next frame. The returned slice is owned by the
	// caller. It returns ErrTimeout when no packet arrived within the poll
	// interval (live sources only) and io.EOF at the end of a file.
	ReadPacket() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	// Dropped returns how many packets the OS or driver dropped, if known.
	Dropped() (uint64, bool)
	Close() error
}

// ErrTimeout is returned by live sources when the poll interval elapsed without a packet.
var ErrTimeout = errors.New("capture: timeout")

// Interface is a network interface that can be captured from.
type Interface struct {
	Name        string       // name to pass to OpenLive
	Description string       // human-friendly description (adapter model on Windows)
	Addrs       []netip.Addr // assigned IP addresses
}

// HotspotGateway is the address Windows Mobile Hotspot (Internet Connection
// Sharing) assigns to the laptop on the hotspot network.
var HotspotGateway = netip.MustParseAddr("192.168.137.1")

// FindHotspot returns the interface that carries the Windows Mobile Hotspot
// network, recognized by its fixed gateway address.
func FindHotspot(ifaces []Interface) (Interface, bool) {
	for _, i := range ifaces {
		for _, a := range i.Addrs {
			if a == HotspotGateway {
				return i, true
			}
		}
	}
	return Interface{}, false
}

// Find returns the interface whose name or description matches name exactly,
// or whose description contains it (case-insensitive) when that is unambiguous.
func Find(ifaces []Interface, name string) (Interface, error) {
	var partial []Interface
	for _, i := range ifaces {
		if i.Name == name || strings.EqualFold(i.Description, name) {
			return i, nil
		}
		if strings.Contains(strings.ToLower(i.Description), strings.ToLower(name)) {
			partial = append(partial, i)
		}
	}
	switch len(partial) {
	case 1:
		return partial[0], nil
	case 0:
		return Interface{}, errors.New("no interface named " + name + " (run with -list to see them)")
	default:
		return Interface{}, errors.New("several interfaces match " + name + "; use the exact name from -list")
	}
}

// IPv4 returns the first IPv4 address of the interface, if any.
func (i Interface) IPv4() (netip.Addr, bool) {
	for _, a := range i.Addrs {
		if a.Is4() {
			return a, true
		}
	}
	return netip.Addr{}, false
}
