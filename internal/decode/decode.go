// Package decode turns raw link-layer frames into a compact, allocation-light
// summary (addresses, ports, TCP flags, application payload) that the rest of
// NetLens works with. It uses gopacket's DecodingLayerParser, which decodes into
// preallocated layer structs instead of building a full gopacket.Packet per frame.
package decode

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Proto is the transport protocol of a packet.
type Proto uint8

const (
	ProtoOther Proto = iota
	ProtoTCP
	ProtoUDP
	ProtoICMP
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMP:
		return "ICMP"
	default:
		return "OTHER"
	}
}

// TCP flag bits, matching their position in the TCP header.
const (
	FlagFIN uint8 = 1 << iota
	FlagSYN
	FlagRST
	FlagPSH
	FlagACK
)

// Packet is the decoded summary of one frame.
//
// Payload aliases the frame buffer passed to Decode: it is only valid until the
// buffer is reused. Callers that keep it must copy it.
type Packet struct {
	Time     time.Time
	Length   int // original length on the wire
	SrcMAC   net.HardwareAddr
	SrcIP    netip.Addr
	DstIP    netip.Addr
	Proto    Proto
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	Seq      uint32
	Payload  []byte
}

// Src returns the source address and port.
func (p *Packet) Src() netip.AddrPort { return netip.AddrPortFrom(p.SrcIP, p.SrcPort) }

// Dst returns the destination address and port.
func (p *Packet) Dst() netip.AddrPort { return netip.AddrPortFrom(p.DstIP, p.DstPort) }

// ErrNotIP is returned for frames that carry no IPv4/IPv6 packet (ARP, LLDP, ...).
var ErrNotIP = errors.New("decode: not an IP packet")

// Decoder decodes frames of a single link type. It is not safe for concurrent use.
type Decoder struct {
	linkType layers.LinkType

	eth   layers.Ethernet
	dot1q layers.Dot1Q
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
	icmp6 layers.ICMPv6

	ethParser *gopacket.DecodingLayerParser
	ip4Parser *gopacket.DecodingLayerParser
	ip6Parser *gopacket.DecodingLayerParser
	decoded   []gopacket.LayerType
}

// New returns a Decoder for frames of the given link type.
func New(linkType layers.LinkType) *Decoder {
	d := &Decoder{linkType: linkType, decoded: make([]gopacket.LayerType, 0, 8)}
	all := []gopacket.DecodingLayer{&d.eth, &d.dot1q, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6}
	d.ethParser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, all...)
	d.ip4Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, all...)
	d.ip6Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, all...)
	for _, p := range []*gopacket.DecodingLayerParser{d.ethParser, d.ip4Parser, d.ip6Parser} {
		// Stop quietly at layers we don't decode (DNS, TLS, IPv6 extension
		// headers, ...): the transport payload is all we need.
		p.IgnoreUnsupported = true
	}
	return d
}

// Decode fills out with the summary of frame. ci supplies the timestamp and wire length.
func (d *Decoder) Decode(frame []byte, ci gopacket.CaptureInfo, out *Packet) error {
	*out = Packet{Time: ci.Timestamp, Length: ci.Length}
	if out.Length == 0 {
		out.Length = len(frame)
	}

	parser, data, err := d.pickParser(frame)
	if err != nil {
		return err
	}
	if err := parser.DecodeLayers(data, &d.decoded); err != nil {
		// Truncated or malformed frame; keep whatever was decoded before the error
		// only if we at least reached the IP layer.
		if !d.has(layers.LayerTypeIPv4) && !d.has(layers.LayerTypeIPv6) {
			return err
		}
	}

	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeEthernet:
			out.SrcMAC = d.eth.SrcMAC
		case layers.LayerTypeIPv4:
			out.SrcIP, _ = netip.AddrFromSlice(d.ip4.SrcIP.To4())
			out.DstIP, _ = netip.AddrFromSlice(d.ip4.DstIP.To4())
		case layers.LayerTypeIPv6:
			out.SrcIP, _ = netip.AddrFromSlice(d.ip6.SrcIP)
			out.DstIP, _ = netip.AddrFromSlice(d.ip6.DstIP)
		case layers.LayerTypeTCP:
			out.Proto = ProtoTCP
			out.SrcPort, out.DstPort = uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
			out.Seq = d.tcp.Seq
			out.TCPFlags = tcpFlags(&d.tcp)
			out.Payload = d.tcp.Payload
		case layers.LayerTypeUDP:
			out.Proto = ProtoUDP
			out.SrcPort, out.DstPort = uint16(d.udp.SrcPort), uint16(d.udp.DstPort)
			out.Payload = d.udp.Payload
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			out.Proto = ProtoICMP
		}
	}
	if !out.SrcIP.IsValid() {
		return ErrNotIP
	}
	return nil
}

func (d *Decoder) has(lt gopacket.LayerType) bool {
	for _, x := range d.decoded {
		if x == lt {
			return true
		}
	}
	return false
}

// pickParser chooses a parser and strips link headers we don't model as layers.
func (d *Decoder) pickParser(frame []byte) (*gopacket.DecodingLayerParser, []byte, error) {
	switch d.linkType {
	case layers.LinkTypeEthernet:
		return d.ethParser, frame, nil
	case layers.LinkTypeNull, layers.LinkTypeLoop: // BSD/Windows loopback: 4-byte family header
		return d.rawIP(frame, 4)
	case layers.LinkTypeLinuxSLL: // Linux "any" device: 16-byte cooked header
		return d.rawIP(frame, 16)
	case layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		return d.rawIP(frame, 0)
	default:
		return nil, nil, errors.New("decode: unsupported link type " + d.linkType.String())
	}
}

func (d *Decoder) rawIP(frame []byte, skip int) (*gopacket.DecodingLayerParser, []byte, error) {
	if len(frame) <= skip {
		return nil, nil, ErrNotIP
	}
	data := frame[skip:]
	switch data[0] >> 4 {
	case 4:
		return d.ip4Parser, data, nil
	case 6:
		return d.ip6Parser, data, nil
	}
	return nil, nil, ErrNotIP
}

func tcpFlags(t *layers.TCP) uint8 {
	var f uint8
	if t.FIN {
		f |= FlagFIN
	}
	if t.SYN {
		f |= FlagSYN
	}
	if t.RST {
		f |= FlagRST
	}
	if t.PSH {
		f |= FlagPSH
	}
	if t.ACK {
		f |= FlagACK
	}
	return f
}
