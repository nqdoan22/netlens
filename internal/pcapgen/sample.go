package pcapgen

import (
	"net"
	"net/netip"
	"time"
)

// Hosts used by Sample.
var (
	Phone  = Host{MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x45}, IP: netip.MustParseAddr("192.168.137.45")}
	Laptop = Host{MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x60}, IP: netip.MustParseAddr("192.168.137.60")}
)

// SampleStart is the timestamp of the first packet in Sample.
var SampleStart = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)

// Sample builds a short, realistic session on a hotspot network: a phone joins,
// resolves names and opens TLS, HTTP and QUIC connections; a second device
// does the same; one connection is reset. It exercises every analyzer.
func Sample() *Builder {
	b := New(SampleStart)
	ap := netip.MustParseAddrPort

	// The phone joins the hotspot and announces its name over DHCP.
	b.DHCPRequest(Phone, "Demo-iPhone")
	b.Advance(200 * time.Millisecond)

	// Bonjour/mDNS chatter: hidden from the default text output.
	b.UDP(Phone, 5353, ap("224.0.0.251:5353"), true, []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	// HTTPS with a ClientHello large enough to span several TCP segments.
	b.DNSLookup(Phone, "www.example.com", 300, netip.MustParseAddr("203.0.113.10"))
	web := b.TCP(Phone, 50001, ap("203.0.113.10:443"))
	web.Send(true, ClientHello("www.example.com", "h2", "http/1.1"), 536)
	web.Send(false, make([]byte, 2800), 1400) // server hello + certificate (opaque here)
	web.Send(true, make([]byte, 120), 1400)
	web.Send(false, make([]byte, 42000), 1400) // page content
	b.Advance(2 * time.Second)
	web.Close()

	// A connection made without a DNS lookup (hard-coded IP): the SNI names it.
	trk := b.TCP(Phone, 50002, ap("192.0.2.50:443"))
	trk.Send(true, ClientHello("tracker.example.org", "http/1.1"), 1400)
	trk.Send(false, make([]byte, 600), 1400)
	trk.Send(true, make([]byte, 3000), 1400) // uploads more than it downloads
	b.Advance(500 * time.Millisecond)
	trk.Close()

	// Clear-text HTTP: the Host header is visible.
	b.DNSLookup(Phone, "http.example.com", 60, netip.MustParseAddr("203.0.113.80"))
	plain := b.TCP(Phone, 50003, ap("203.0.113.80:80"))
	plain.Send(true, []byte("GET /index.html HTTP/1.1\r\nHost: http.example.com\r\nUser-Agent: Demo\r\n\r\n"), 1400)
	plain.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"), 1400)
	plain.Close()

	// QUIC (HTTP/3) over UDP 443: named from the earlier DNS answer.
	b.DNSLookup(Phone, "video.example.com", 120, netip.MustParseAddr("198.51.100.30"))
	quicInitial := append([]byte{0xc3, 0, 0, 0, 1}, make([]byte, 1195)...)
	b.UDP(Phone, 60001, ap("198.51.100.30:443"), true, quicInitial)
	for i := 0; i < 20; i++ {
		b.UDP(Phone, 60001, ap("198.51.100.30:443"), false, append([]byte{0x40}, make([]byte, 1250)...))
	}
	b.UDP(Phone, 60001, ap("198.51.100.30:443"), true, append([]byte{0x40}, make([]byte, 40)...))

	// A server that resets the connection right after the handshake.
	b.DNSLookup(Phone, "broken.example.net", 300, netip.MustParseAddr("198.51.100.99"))
	rst := b.TCP(Phone, 50004, ap("198.51.100.99:443"))
	rst.Reset()

	// A second device joins and does its own lookups.
	b.DHCPRequest(Laptop, "Demo-Laptop")
	b.DNSLookup(Laptop, "updates.example.com", 300, netip.MustParseAddr("203.0.113.200"))
	upd := b.TCP(Laptop, 51000, ap("203.0.113.200:443"))
	upd.Send(true, ClientHello("updates.example.com", "h2"), 1400)
	upd.Send(false, make([]byte, 8000), 1400)
	b.Advance(time.Second)
	upd.Close()

	// Clock sync: an NTP exchange.
	b.DNSLookup(Phone, "time.example.com", 300, netip.MustParseAddr("192.0.2.123"))
	b.UDP(Phone, 61000, ap("192.0.2.123:123"), true, make([]byte, 48))
	b.UDP(Phone, 61000, ap("192.0.2.123:123"), false, make([]byte, 48))

	return b
}
