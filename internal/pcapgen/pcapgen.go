// Package pcapgen builds synthetic captures for tests and demos: DHCP, DNS,
// TCP connections carrying real TLS ClientHellos or HTTP requests, and UDP.
// All addresses come from documentation ranges (RFC 5737, RFC 3849) and all
// host names from reserved domains (RFC 2606), so no real traffic is included.
package pcapgen

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Frame is one serialized Ethernet frame with its timestamp.
type Frame struct {
	Time time.Time
	Data []byte
}

// Builder accumulates frames on a simulated hotspot network.
type Builder struct {
	Now        time.Time
	GatewayMAC net.HardwareAddr
	GatewayIP  netip.Addr
	Frames     []Frame
}

// New returns a Builder for a Windows-hotspot-like network (gateway 192.168.137.1).
func New(start time.Time) *Builder {
	return &Builder{
		Now:        start,
		GatewayMAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		GatewayIP:  netip.MustParseAddr("192.168.137.1"),
	}
}

// Advance moves the clock forward.
func (b *Builder) Advance(d time.Duration) { b.Now = b.Now.Add(d) }

// Host is a device on the simulated network.
type Host struct {
	MAC net.HardwareAddr
	IP  netip.Addr
}

func (b *Builder) add(ls ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	for _, l := range ls {
		if t, ok := l.(*layers.TCP); ok {
			_ = t.SetNetworkLayerForChecksum(ls[1].(gopacket.NetworkLayer))
		}
		if u, ok := l.(*layers.UDP); ok {
			_ = u.SetNetworkLayerForChecksum(ls[1].(gopacket.NetworkLayer))
		}
	}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		panic(err)
	}
	b.Frames = append(b.Frames, Frame{Time: b.Now, Data: append([]byte(nil), buf.Bytes()...)})
	b.Advance(time.Millisecond)
}

func (b *Builder) eth(src, dst net.HardwareAddr, v6 bool) *layers.Ethernet {
	et := layers.EthernetTypeIPv4
	if v6 {
		et = layers.EthernetTypeIPv6
	}
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: et}
}

func ipLayer(src, dst netip.Addr, proto layers.IPProtocol) gopacket.SerializableLayer {
	if src.Is4() {
		return &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	}
	return &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
}

// macs returns the frame MACs for traffic from h towards the gateway (or back).
func (b *Builder) macs(h Host, fromHost bool) (net.HardwareAddr, net.HardwareAddr) {
	if fromHost {
		return h.MAC, b.GatewayMAC
	}
	return b.GatewayMAC, h.MAC
}

// UDP adds one UDP datagram between host h and a remote endpoint.
func (b *Builder) UDP(h Host, hostPort uint16, remote netip.AddrPort, fromHost bool, payload []byte) {
	src, dst := netip.AddrPortFrom(h.IP, hostPort), remote
	if !fromHost {
		src, dst = dst, src
	}
	sm, dm := b.macs(h, fromHost)
	b.add(b.eth(sm, dm, !src.Addr().Is4()),
		ipLayer(src.Addr(), dst.Addr(), layers.IPProtocolUDP),
		&layers.UDP{SrcPort: layers.UDPPort(src.Port()), DstPort: layers.UDPPort(dst.Port())},
		gopacket.Payload(payload))
}

// DHCPRequest adds a DHCP Request broadcast carrying the client's hostname.
func (b *Builder) DHCPRequest(h Host, hostname string) {
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x1234,
		ClientHWAddr: h.MAC,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
			layers.NewDHCPOption(layers.DHCPOptRequestIP, h.IP.AsSlice()),
			layers.NewDHCPOption(layers.DHCPOptHostname, []byte(hostname)),
		},
	}
	b.add(b.eth(h.MAC, layers.EthernetBroadcast, false),
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4zero.To4(), DstIP: net.IPv4bcast.To4()},
		&layers.UDP{SrcPort: 68, DstPort: 67},
		dhcp)
}

// DNSLookup adds a query from h to the gateway and its response.
func (b *Builder) DNSLookup(h Host, name string, ttl uint32, answers ...netip.Addr) {
	const port = 53001
	q := layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	if len(answers) > 0 && answers[0].Is6() {
		q.Type = layers.DNSTypeAAAA
	}
	query := &layers.DNS{ID: uint16(len(b.Frames)), RD: true, Questions: []layers.DNSQuestion{q}}
	server := netip.AddrPortFrom(b.GatewayIP, 53)
	b.UDP(h, port, server, true, serializeDNS(query))

	resp := &layers.DNS{ID: query.ID, QR: true, RD: true, RA: true, Questions: query.Questions}
	for _, a := range answers {
		rr := layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: ttl, IP: a.AsSlice()}
		if a.Is6() {
			rr.Type = layers.DNSTypeAAAA
		}
		resp.Answers = append(resp.Answers, rr)
	}
	resp.ANCount = uint16(len(resp.Answers))
	b.Advance(15 * time.Millisecond)
	b.UDP(h, port, server, false, serializeDNS(resp))
}

func serializeDNS(d *layers.DNS) []byte {
	d.QDCount = uint16(len(d.Questions))
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		panic(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// TCPConn simulates one TCP connection between a host and a server.
type TCPConn struct {
	b              *Builder
	h              Host
	client, server netip.AddrPort
	cseq, sseq     uint32
}

// TCP opens a connection with a three-way handshake.
func (b *Builder) TCP(h Host, clientPort uint16, server netip.AddrPort) *TCPConn {
	c := &TCPConn{b: b, h: h, client: netip.AddrPortFrom(h.IP, clientPort), server: server, cseq: 1000, sseq: 5000}
	c.seg(true, layers.TCP{SYN: true}, nil)
	c.seg(false, layers.TCP{SYN: true, ACK: true}, nil)
	c.seg(true, layers.TCP{ACK: true}, nil)
	return c
}

func (c *TCPConn) seg(fromClient bool, t layers.TCP, payload []byte) {
	src, dst := c.client, c.server
	seq, ack := &c.cseq, c.sseq
	if !fromClient {
		src, dst = dst, src
		seq, ack = &c.sseq, c.cseq
	}
	t.SrcPort, t.DstPort = layers.TCPPort(src.Port()), layers.TCPPort(dst.Port())
	t.Seq, t.Window = *seq, 65535
	if t.ACK {
		t.Ack = ack
	}
	sm, dm := c.b.macs(c.h, fromClient)
	c.b.add(c.b.eth(sm, dm, !src.Addr().Is4()), ipLayer(src.Addr(), dst.Addr(), layers.IPProtocolTCP), &t, gopacket.Payload(payload))
	*seq += uint32(len(payload))
	if t.SYN || t.FIN {
		*seq++
	}
}

// Send transmits payload, split into segments of at most mss bytes.
func (c *TCPConn) Send(fromClient bool, payload []byte, mss int) {
	for len(payload) > 0 {
		n := min(mss, len(payload))
		c.seg(fromClient, layers.TCP{ACK: true, PSH: n == len(payload)}, payload[:n])
		payload = payload[n:]
	}
}

// Close performs a FIN/ACK exchange initiated by the client.
func (c *TCPConn) Close() {
	c.seg(true, layers.TCP{FIN: true, ACK: true}, nil)
	c.seg(false, layers.TCP{FIN: true, ACK: true}, nil)
	c.seg(true, layers.TCP{ACK: true}, nil)
}

// Reset aborts the connection from the server side.
func (c *TCPConn) Reset() {
	c.seg(false, layers.TCP{RST: true}, nil)
}

// ClientHello returns the bytes a real Go TLS client sends first when
// connecting to serverName and offering alpn.
func ClientHello(serverName string, alpn ...string) []byte {
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: serverName, NextProtos: alpn, MinVersion: tls.VersionTLS12})
		_ = conn.Handshake() // fails once the pipe closes; we only want the hello
		client.Close()
	}()
	var out []byte
	buf := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := server.Read(buf)
		out = append(out, buf[:n]...)
		if complete(out) || err != nil {
			return out
		}
	}
}

// complete reports whether out holds a whole TLS record.
func complete(out []byte) bool {
	return len(out) >= 5 && len(out) >= 5+(int(out[3])<<8|int(out[4]))
}

// WritePcap writes the frames as a classic pcap file.
func (b *Builder) WritePcap(w io.Writer) error {
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	for _, f := range b.Frames {
		ci := gopacket.CaptureInfo{Timestamp: f.Time, CaptureLength: len(f.Data), Length: len(f.Data)}
		if err := pw.WritePacket(ci, f.Data); err != nil {
			return err
		}
	}
	return nil
}
