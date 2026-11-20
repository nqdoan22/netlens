// Package engine is the analysis pipeline: it decodes frames, tracks devices and
// flows, reads DNS/DHCP/TLS/HTTP metadata, labels each flow with the host it
// talks to, and reports everything as Events.
package engine

import (
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/nqdoan22/netlens/internal/decode"
	"github.com/nqdoan22/netlens/internal/device"
	"github.com/nqdoan22/netlens/internal/dnscache"
	"github.com/nqdoan22/netlens/internal/flow"
	"github.com/nqdoan22/netlens/internal/proto"
)

const (
	// maxInspectBytes bounds how much of a client stream is buffered while
	// waiting for a complete ClientHello or HTTP header block.
	maxInspectBytes = 16 << 10
	// maxInspectSegments bounds how many client segments are inspected.
	maxInspectSegments = 8
	// expireEvery is how often idle flows are swept, in packet time.
	expireEvery = time.Second
)

// Options configures an Engine.
type Options struct {
	// Gateway is the address of the capturing machine on the monitored network
	// (192.168.137.1 for a Windows Mobile Hotspot). It is not reported as a device.
	Gateway netip.Addr
}

// Stats are running counters.
type Stats struct {
	Packets      uint64 `json:"packets"`
	Bytes        uint64 `json:"bytes"`
	NonIP        uint64 `json:"non_ip"`
	DecodeErrors uint64 `json:"decode_errors"`
	Flows        uint64 `json:"flows"`
	DNSResponses uint64 `json:"dns_responses"`
	Devices      int    `json:"devices"`
	ActiveFlows  int    `json:"active_flows"`
}

// Engine processes frames from one capture source. It is not safe for
// concurrent use: feed it from a single goroutine.
type Engine struct {
	opts  Options
	emit  func(Event)
	dec   *decode.Decoder
	flows *flow.Tracker
	dns   *dnscache.Cache
	devs  *device.Registry
	dnsp  proto.DNSParser
	dhcpp proto.DHCPParser

	pkt        decode.Packet
	stats      Stats
	lastExpire time.Time
}

// New returns an Engine for frames of linkType that reports events to emit.
func New(linkType layers.LinkType, opts Options, emit func(Event)) *Engine {
	e := &Engine{
		opts:  opts,
		emit:  emit,
		dec:   decode.New(linkType),
		flows: flow.NewTracker(),
		dns:   dnscache.New(),
		devs:  device.NewRegistry(),
	}
	e.flows.OnStart = e.onFlowStart
	e.flows.OnEnd = e.onFlowEnd
	return e
}

// Process analyzes one captured frame.
func (e *Engine) Process(frame []byte, ci gopacket.CaptureInfo) {
	p := &e.pkt
	if err := e.dec.Decode(frame, ci, p); err != nil {
		if err == decode.ErrNotIP {
			e.stats.NonIP++
		} else {
			e.stats.DecodeErrors++
		}
		return
	}
	e.stats.Packets++
	e.stats.Bytes += uint64(p.Length)

	if p.Proto == decode.ProtoUDP && isDHCP(p) {
		e.handleDHCP(p)
	}

	f, fromClient := e.flows.Update(p)
	if fromClient {
		e.observeDevice(p.Time, p.SrcIP, p.SrcMAC)
	}

	switch {
	case p.Proto == decode.ProtoUDP && (p.SrcPort == 53 || p.DstPort == 53):
		e.handleDNS(p)
	case p.Proto == decode.ProtoTCP && fromClient && !f.Inspect.Done:
		e.inspectTCP(f, p)
	}

	if p.Time.Sub(e.lastExpire) >= expireEvery {
		e.Tick(p.Time)
	}
}

// Tick expires idle and closed flows as of now. Live captures should call it
// periodically so flows end even when no packets arrive.
func (e *Engine) Tick(now time.Time) {
	e.lastExpire = now
	e.flows.Expire(now)
}

// Close ends all open flows. Call it once when the capture stops.
func (e *Engine) Close() {
	e.flows.Flush()
}

// Stats returns a snapshot of the counters.
func (e *Engine) Stats() Stats {
	s := e.stats
	s.Devices = len(e.devs.All())
	s.ActiveFlows = e.flows.Len()
	return s
}

// observeDevice records a local device that opened a flow. Devices are learned
// from the flows they initiate, so servers on the local network (the hotspot's
// own DNS proxy, for instance) are not mistaken for devices.
func (e *Engine) observeDevice(now time.Time, ip netip.Addr, mac net.HardwareAddr) {
	// Only private unicast addresses: link-local IPv6 and 0.0.0.0 (DHCP) would
	// create duplicate entries for the same device.
	if !ip.IsPrivate() || ip == e.opts.Gateway {
		return
	}
	d, isNew := e.devs.Observe(now, ip, mac)
	if isNew {
		e.emit(Event{Kind: KindDevice, Time: now, Device: deviceInfo(d)})
	}
}

func (e *Engine) handleDHCP(p *decode.Packet) {
	m, err := e.dhcpp.Parse(p.Payload)
	if err != nil || m.Hostname == "" {
		return
	}
	ip := m.Requested
	if m.YourIP.IsValid() {
		ip = m.YourIP
	}
	before := ""
	if d, ok := e.devs.Get(ip); ok {
		before = d.Hostname
	}
	e.devs.LearnHostname(p.Time, m.ClientMAC, ip, m.Hostname)
	if d, ok := e.devs.Get(ip); ok && d.Hostname != before {
		e.emit(Event{Kind: KindDevice, Time: p.Time, Device: deviceInfo(d)})
	}
}

func (e *Engine) handleDNS(p *decode.Packet) {
	if len(p.Payload) == 0 || p.SrcPort != 53 { // only responses carry answers
		return
	}
	m, err := e.dnsp.Parse(p.Payload)
	if err != nil || !m.Response || m.Name == "" {
		return
	}
	e.stats.DNSResponses++
	client := p.DstIP
	for _, a := range m.Answers {
		// Label connections with the name the app asked for, not the CNAME target.
		e.dns.Add(p.Time, client, m.Name, a.Addr, a.TTL)
	}
	e.emit(Event{Kind: KindDNS, Time: p.Time, DNS: e.dnsInfo(client, m)})
}

// inspectTCP buffers the start of the client→server stream until the TLS
// ClientHello or HTTP request headers can be parsed.
func (e *Engine) inspectTCP(f *flow.Flow, p *decode.Packet) {
	in := &f.Inspect
	if len(p.Payload) == 0 {
		return
	}
	if !in.Started {
		if !proto.LooksLikeTLS(p.Payload) && !proto.LooksLikeHTTP(p.Payload) {
			e.finishInspect(f)
			return
		}
		in.Started = true
		in.NextSeq = p.Seq
	}
	switch {
	case p.Seq == in.NextSeq:
		in.Buf = append(in.Buf, p.Payload...)
		in.NextSeq += uint32(len(p.Payload))
	case int32(p.Seq-in.NextSeq) < 0:
		return // retransmission of data we already have
	default:
		e.finishInspect(f) // gap: a segment was lost or reordered; give up
		return
	}
	in.Segments++

	var err error
	if proto.LooksLikeTLS(in.Buf) {
		var ch *proto.ClientHello
		if ch, err = proto.ParseClientHello(in.Buf); err == nil {
			f.App = "tls"
			f.ALPN = ch.ALPN
			f.ECH = ch.ECH
			if ch.SNI != "" {
				f.Host, f.HostSource = ch.SNI, "sni"
			}
		}
	} else {
		var req *proto.HTTPRequest
		if req, err = proto.ParseHTTPRequest(in.Buf); err == nil {
			f.App = "http"
			if req.Host != "" {
				f.Host, f.HostSource = req.Host, "http"
			}
		}
	}
	if err == proto.ErrNeedMore && len(in.Buf) < maxInspectBytes && in.Segments < maxInspectSegments {
		return
	}
	e.finishInspect(f)
}

func (e *Engine) finishInspect(f *flow.Flow) {
	f.Inspect.Done = true
	f.Inspect.Buf = nil
	e.emit(Event{Kind: KindFlowUpdate, Time: f.Last, Flow: e.flowInfo(f, "")})
}

func (e *Engine) onFlowStart(f *flow.Flow) {
	e.stats.Flows++
	// Register the client before announcing the flow so the flow carries its name.
	var mac net.HardwareAddr
	if e.pkt.Src() == f.Client {
		mac = e.pkt.SrcMAC
	}
	e.observeDevice(f.Start, f.Client.Addr(), mac)
	f.App = guessApp(f)
	if name, ok := e.dns.Lookup(f.Start, f.Client.Addr(), f.Server.Addr()); ok {
		f.Host, f.HostSource = name, "dns"
	}
	if f.Proto != decode.ProtoTCP {
		f.Inspect.Done = true // only TCP streams are inspected for now
	}
	e.emit(Event{Kind: KindFlowStart, Time: f.Start, Flow: e.flowInfo(f, "")})
}

func (e *Engine) onFlowEnd(f *flow.Flow, reason flow.EndReason) {
	e.emit(Event{Kind: KindFlowEnd, Time: f.Last, Flow: e.flowInfo(f, reason)})
}

func isDHCP(p *decode.Packet) bool {
	return (p.SrcPort == 67 || p.SrcPort == 68) && (p.DstPort == 67 || p.DstPort == 68)
}

// guessApp labels a flow from its server port until inspection knows better.
func guessApp(f *flow.Flow) string {
	port := f.Server.Port()
	switch f.Proto {
	case decode.ProtoUDP:
		switch port {
		case 53:
			return "dns"
		case 67, 68:
			return "dhcp"
		case 123:
			return "ntp"
		case 443:
			return "quic"
		case 853:
			return "dns-over-quic"
		case 1900:
			return "ssdp"
		case 5353:
			return "mdns"
		case 5355:
			return "llmnr"
		case 137, 138:
			return "netbios"
		}
	case decode.ProtoTCP:
		switch port {
		case 53:
			return "dns"
		case 853:
			return "dns-over-tls"
		}
	case decode.ProtoICMP:
		return "icmp"
	}
	return ""
}

func (e *Engine) deviceLabel(ip netip.Addr) string {
	if ip == e.opts.Gateway {
		return "gateway"
	}
	if d, ok := e.devs.Get(ip); ok {
		return d.Label()
	}
	return ip.String()
}
