package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nqdoan22/netlens/internal/decode"
)

var (
	t0     = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	phone  = netip.MustParseAddrPort("192.168.137.45:50000")
	server = netip.MustParseAddrPort("203.0.113.10:443")
)

func tcp(at time.Duration, src, dst netip.AddrPort, flags uint8, size int) *decode.Packet {
	return &decode.Packet{
		Time: t0.Add(at), Length: size, Proto: decode.ProtoTCP, TCPFlags: flags,
		SrcIP: src.Addr(), DstIP: dst.Addr(), SrcPort: src.Port(), DstPort: dst.Port(),
	}
}

func udp(at time.Duration, src, dst netip.AddrPort, size int) *decode.Packet {
	p := tcp(at, src, dst, 0, size)
	p.Proto = decode.ProtoUDP
	return p
}

type recorder struct {
	started []*Flow
	ended   map[uint64]EndReason
}

func newTracker() (*Tracker, *recorder) {
	r := &recorder{ended: map[uint64]EndReason{}}
	t := NewTracker()
	t.OnStart = func(f *Flow) { r.started = append(r.started, f) }
	t.OnEnd = func(f *Flow, reason EndReason) {
		if _, dup := r.ended[f.ID]; dup {
			panic("OnEnd called twice")
		}
		r.ended[f.ID] = reason
	}
	return t, r
}

func TestTCPLifecycle(t *testing.T) {
	tr, rec := newTracker()
	const syn, ack, fin = decode.FlagSYN, decode.FlagACK, decode.FlagFIN

	tr.Update(tcp(0, phone, server, syn, 60))
	tr.Update(tcp(10*time.Millisecond, server, phone, syn|ack, 60))
	tr.Update(tcp(20*time.Millisecond, phone, server, ack, 52))
	tr.Update(tcp(30*time.Millisecond, server, phone, ack, 1500))
	f, _ := tr.Update(tcp(40*time.Millisecond, phone, server, fin|ack, 52))
	if len(rec.ended) != 0 {
		t.Fatal("flow ended after a single FIN")
	}
	tr.Update(tcp(50*time.Millisecond, server, phone, fin|ack, 52))
	if rec.ended[f.ID] != EndFIN {
		t.Fatalf("after FIN both ways: ended = %v, want fin", rec.ended)
	}
	tr.Update(tcp(60*time.Millisecond, phone, server, ack, 52)) // final ACK is absorbed

	if len(rec.started) != 1 {
		t.Fatalf("started %d flows, want 1", len(rec.started))
	}
	if f.Client != phone || f.Server != server {
		t.Errorf("client/server = %v/%v", f.Client, f.Server)
	}
	if f.PktsOut != 4 || f.PktsIn != 3 || f.BytesIn != 1612 {
		t.Errorf("out %d pkts, in %d pkts / %d bytes", f.PktsOut, f.PktsIn, f.BytesIn)
	}

	tr.Expire(t0.Add(time.Minute))
	if tr.Len() != 0 {
		t.Errorf("closed flow still tracked after linger")
	}
}

func TestRSTEndsFlow(t *testing.T) {
	tr, rec := newTracker()
	f, _ := tr.Update(tcp(0, phone, server, decode.FlagSYN, 60))
	tr.Update(tcp(time.Millisecond, server, phone, decode.FlagRST, 40))
	if rec.ended[f.ID] != EndRST {
		t.Fatalf("ended = %v, want rst", rec.ended)
	}
}

// When the capture starts mid-connection, the first packet may come from the
// server; the local device must still be recognized as the client.
func TestMidStreamDirection(t *testing.T) {
	tr, _ := newTracker()
	f, fromClient := tr.Update(tcp(0, server, phone, decode.FlagACK, 1500))
	if fromClient || f.Client != phone {
		t.Fatalf("client = %v, fromClient = %v; want %v, false", f.Client, fromClient, phone)
	}
}

func TestLocalServiceDirection(t *testing.T) {
	tr, _ := newTracker()
	dns := netip.MustParseAddrPort("192.168.137.1:53")
	// Both sides are local: the service port decides, even for the response.
	f, _ := tr.Update(udp(0, dns, netip.MustParseAddrPort("192.168.137.45:53001"), 120))
	if f.Server != dns {
		t.Fatalf("server = %v, want %v", f.Server, dns)
	}
}

func TestIdleExpiryAndFlush(t *testing.T) {
	tr, rec := newTracker()
	quic := netip.MustParseAddrPort("198.51.100.30:443")
	u, _ := tr.Update(udp(0, phone, quic, 1200))
	c, _ := tr.Update(tcp(0, phone, server, decode.FlagSYN, 60))

	tr.Expire(t0.Add(DefaultTimeouts.UDPIdle - time.Second))
	if len(rec.ended) != 0 {
		t.Fatal("flow expired early")
	}
	tr.Expire(t0.Add(DefaultTimeouts.UDPIdle))
	if rec.ended[u.ID] != EndIdle {
		t.Fatalf("UDP flow: ended = %v, want idle", rec.ended)
	}
	tr.Flush()
	if rec.ended[c.ID] != EndShutdown || tr.Len() != 0 {
		t.Fatalf("after Flush: ended = %v, tracked = %d", rec.ended, tr.Len())
	}
}

func TestPortReuseStartsNewFlow(t *testing.T) {
	tr, rec := newTracker()
	first, _ := tr.Update(tcp(0, phone, server, decode.FlagSYN, 60))
	tr.Update(tcp(time.Millisecond, server, phone, decode.FlagRST, 40))
	second, _ := tr.Update(tcp(2*time.Millisecond, phone, server, decode.FlagSYN, 60))
	if second == first || len(rec.started) != 2 {
		t.Fatalf("SYN after RST reused the old flow")
	}
}
