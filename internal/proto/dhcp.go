package proto

import (
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// DHCPMessage is the summary of a DHCPv4 message that helps name a device.
type DHCPMessage struct {
	Type      string // "Discover", "Request", "Ack", ...
	ClientMAC net.HardwareAddr
	Hostname  string     // option 12, sent by most clients (e.g. "Johns-iPhone")
	YourIP    netip.Addr // address assigned by the server (Offer/Ack)
	Requested netip.Addr // option 50, address the client asks for
}

// DHCPParser decodes DHCPv4 messages. It is not safe for concurrent use.
type DHCPParser struct {
	dhcp layers.DHCPv4
}

// Parse decodes a DHCPv4 message carried over UDP ports 67/68.
func (p *DHCPParser) Parse(payload []byte) (*DHCPMessage, error) {
	if err := p.dhcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	d := &p.dhcp
	m := &DHCPMessage{ClientMAC: append(net.HardwareAddr(nil), d.ClientHWAddr...)}
	if ip, ok := netip.AddrFromSlice(d.YourClientIP.To4()); ok && !ip.IsUnspecified() {
		m.YourIP = ip
	}
	for _, o := range d.Options {
		switch o.Type {
		case layers.DHCPOptMessageType:
			if len(o.Data) == 1 {
				m.Type = layers.DHCPMsgType(o.Data[0]).String()
			}
		case layers.DHCPOptHostname:
			m.Hostname = string(o.Data)
		case layers.DHCPOptRequestIP:
			if ip, ok := netip.AddrFromSlice(o.Data); ok {
				m.Requested = ip
			}
		}
	}
	return m, nil
}
