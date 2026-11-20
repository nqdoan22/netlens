// Package flow groups packets into bidirectional flows ("connections"),
// identified by their 5-tuple, and decides which side opened each flow.
package flow

import (
	"net/netip"
	"time"

	"github.com/nqdoan22/netlens/internal/decode"
	"github.com/nqdoan22/netlens/internal/device"
)

// EndReason says why a flow ended.
type EndReason string

const (
	EndFIN      EndReason = "fin"         // TCP closed normally by both sides
	EndRST      EndReason = "rst"         // TCP reset
	EndIdle     EndReason = "idle"        // no packets for the idle timeout
	EndShutdown EndReason = "capture_end" // capture stopped while the flow was open
)

// Timeouts controls when flows are considered finished.
type Timeouts struct {
	TCPIdle   time.Duration // established TCP flow with no packets
	UDPIdle   time.Duration // UDP/ICMP/other flow with no packets
	TCPLinger time.Duration // keep a closed TCP flow briefly to absorb its final ACKs
}

// DefaultTimeouts are reasonable values for interactive traffic.
var DefaultTimeouts = Timeouts{
	TCPIdle:   5 * time.Minute,
	UDPIdle:   60 * time.Second,
	TCPLinger: 5 * time.Second,
}

// Key identifies a flow regardless of packet direction: A is always the
// smaller endpoint.
type Key struct {
	Proto decode.Proto
	A, B  netip.AddrPort
}

// KeyOf returns the direction-independent key of a packet.
func KeyOf(p *decode.Packet) Key {
	a, b := p.Src(), p.Dst()
	if b.Compare(a) < 0 {
		a, b = b, a
	}
	return Key{Proto: p.Proto, A: a, B: b}
}

// Inspect is per-flow scratch state used by application-protocol inspection
// (e.g. buffering the first client bytes until a TLS ClientHello is complete).
type Inspect struct {
	Done     bool   // inspection finished (identified or gave up)
	Buf      []byte // in-order client→server bytes collected so far
	NextSeq  uint32 // next expected TCP sequence number from the client
	Started  bool
	Segments int
}

// Flow is one bidirectional conversation between a client and a server.
type Flow struct {
	ID     uint64
	Proto  decode.Proto
	Client netip.AddrPort // side that opened the flow
	Server netip.AddrPort
	Start  time.Time
	Last   time.Time

	PktsOut, PktsIn   uint64 // client→server / server→client
	BytesOut, BytesIn uint64 // wire bytes, including headers

	// Labels filled in by the engine.
	Host       string   // destination host name, if known
	HostSource string   // "dns", "sni", "http"
	App        string   // "tls", "http", "dns", "quic", ...
	ALPN       []string // TLS application protocols offered by the client
	ECH        bool     // TLS Encrypted Client Hello in use: real SNI hidden

	Inspect Inspect

	key        Key
	synSeen    bool
	finClient  bool
	finServer  bool
	closedAt   time.Time // set when the TCP flow closed (FIN both ways or RST)
	closeCause EndReason
	reported   bool // OnEnd already called; the entry only lingers to absorb late packets
}

// Duration is the time between the first and last packet.
func (f *Flow) Duration() time.Duration { return f.Last.Sub(f.Start) }

// Closed reports whether the TCP flow has been closed by FIN or RST.
func (f *Flow) Closed() bool { return !f.closedAt.IsZero() }

// Tracker owns the table of active flows. It is not safe for concurrent use.
type Tracker struct {
	Timeouts Timeouts
	// OnStart is called when a new flow is created, before its first packet is counted.
	OnStart func(f *Flow)
	// OnEnd is called once when a flow ends: as soon as a TCP flow closes, or
	// when a flow goes idle or the capture stops.
	OnEnd func(f *Flow, reason EndReason)

	flows  map[Key]*Flow
	nextID uint64
}

// NewTracker returns an empty tracker using DefaultTimeouts.
func NewTracker() *Tracker {
	return &Tracker{Timeouts: DefaultTimeouts, flows: make(map[Key]*Flow)}
}

// Len returns the number of active flows.
func (t *Tracker) Len() int { return len(t.flows) }

// Update accounts packet p to its flow, creating the flow if needed. It returns
// the flow and whether p travels from the client to the server.
func (t *Tracker) Update(p *decode.Packet) (f *Flow, fromClient bool) {
	k := KeyOf(p)
	f = t.flows[k]

	// A fresh SYN on a closed flow means the 5-tuple is being reused.
	if f != nil && f.Closed() && p.Proto == decode.ProtoTCP && isPureSYN(p.TCPFlags) {
		t.remove(f)
		f = nil
	}
	if f == nil {
		f = t.newFlow(k, p)
	}

	fromClient = p.Src() == f.Client
	f.Last = p.Time
	if fromClient {
		f.PktsOut++
		f.BytesOut += uint64(p.Length)
	} else {
		f.PktsIn++
		f.BytesIn += uint64(p.Length)
	}
	if p.Proto == decode.ProtoTCP {
		t.updateTCPState(f, p, fromClient)
	}
	return f, fromClient
}

func (t *Tracker) newFlow(k Key, p *decode.Packet) *Flow {
	t.nextID++
	client, server := p.Src(), p.Dst()
	if !srcIsClient(p) {
		client, server = server, client
	}
	f := &Flow{
		ID:     t.nextID,
		Proto:  p.Proto,
		Client: client,
		Server: server,
		Start:  p.Time,
		Last:   p.Time,
		key:    k,
	}
	t.flows[k] = f
	if t.OnStart != nil {
		t.OnStart(f)
	}
	return f
}

func (t *Tracker) updateTCPState(f *Flow, p *decode.Packet, fromClient bool) {
	if p.TCPFlags&decode.FlagSYN != 0 {
		f.synSeen = true
	}
	if p.TCPFlags&decode.FlagFIN != 0 {
		if fromClient {
			f.finClient = true
		} else {
			f.finServer = true
		}
	}
	if f.Closed() {
		return
	}
	switch {
	case p.TCPFlags&decode.FlagRST != 0:
		f.closedAt, f.closeCause = p.Time, EndRST
	case f.finClient && f.finServer:
		f.closedAt, f.closeCause = p.Time, EndFIN
	default:
		return
	}
	t.report(f, f.closeCause)
}

// Expire ends flows that closed or went idle as of now. Call it periodically
// with the current time (live capture) or the latest packet time (file replay).
func (t *Tracker) Expire(now time.Time) {
	for _, f := range t.flows {
		switch {
		case f.Closed() && now.Sub(f.closedAt) >= t.Timeouts.TCPLinger:
			t.remove(f)
		case !f.Closed() && now.Sub(f.Last) >= t.idleTimeout(f):
			t.report(f, EndIdle)
			t.remove(f)
		}
	}
}

// Flush ends every remaining flow, e.g. when the capture stops.
func (t *Tracker) Flush() {
	for _, f := range t.flows {
		t.report(f, EndShutdown)
		t.remove(f)
	}
}

func (t *Tracker) idleTimeout(f *Flow) time.Duration {
	if f.Proto == decode.ProtoTCP {
		return t.Timeouts.TCPIdle
	}
	return t.Timeouts.UDPIdle
}

// report calls OnEnd once per flow.
func (t *Tracker) report(f *Flow, reason EndReason) {
	if f.reported {
		return
	}
	f.reported = true
	if t.OnEnd != nil {
		t.OnEnd(f, reason)
	}
}

func (t *Tracker) remove(f *Flow) { delete(t.flows, f.key) }

func isPureSYN(flags uint8) bool {
	return flags&decode.FlagSYN != 0 && flags&decode.FlagACK == 0
}

// srcIsClient decides whether the sender of the first packet seen for a flow
// opened it. Captures can start mid-connection, so the SYN is not always seen.
func srcIsClient(p *decode.Packet) bool {
	if p.Proto == decode.ProtoTCP && p.TCPFlags&decode.FlagSYN != 0 {
		return p.TCPFlags&decode.FlagACK == 0 // SYN → client, SYN-ACK → server
	}
	srcLocal, dstLocal := device.IsLocal(p.SrcIP), device.IsLocal(p.DstIP)
	if srcLocal != dstLocal {
		return srcLocal // devices on the monitored network talk to the Internet
	}
	srcSvc, dstSvc := isServicePort(p.SrcPort), isServicePort(p.DstPort)
	if srcSvc != dstSvc {
		return dstSvc
	}
	return p.SrcPort >= p.DstPort // clients usually use high ephemeral ports
}

func isServicePort(port uint16) bool {
	switch port {
	case 53, 67, 68, 80, 123, 443, 853, 1900, 5353, 8080, 8443:
		return true
	}
	return port != 0 && port < 1024
}
