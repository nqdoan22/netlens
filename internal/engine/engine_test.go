package engine

import (
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/nqdoan22/netlens/internal/capture"
	"github.com/nqdoan22/netlens/internal/pcapgen"
)

// run feeds frames through a fresh engine and returns its events and stats.
func run(t testing.TB, frames []pcapgen.Frame) ([]Event, Stats) {
	t.Helper()
	var events []Event
	e := New(layers.LinkTypeEthernet, Options{Gateway: capture.HotspotGateway}, func(ev Event) {
		events = append(events, ev)
	})
	for _, f := range frames {
		e.Process(f.Data, gopacket.CaptureInfo{Timestamp: f.Time, CaptureLength: len(f.Data), Length: len(f.Data)})
	}
	e.Close()
	return events, e.Stats()
}

// ended returns the flow_end event of each flow, keyed by host (or server).
func ended(events []Event) map[string]*FlowInfo {
	out := map[string]*FlowInfo{}
	for _, ev := range events {
		if ev.Kind == KindFlowEnd {
			key := ev.Flow.Host
			if key == "" {
				key = ev.Flow.Server
			}
			out[key] = ev.Flow
		}
	}
	return out
}

func TestSampleSession(t *testing.T) {
	events, stats := run(t, pcapgen.Sample().Frames)
	flows := ended(events)

	tests := []struct {
		host, device, app, source, reason string
		alpn                              []string
	}{
		{"www.example.com", "Demo-iPhone", "tls", "sni", "fin", []string{"h2", "http/1.1"}},
		{"tracker.example.org", "Demo-iPhone", "tls", "sni", "fin", []string{"http/1.1"}},
		{"http.example.com", "Demo-iPhone", "http", "http", "fin", nil},
		{"video.example.com", "Demo-iPhone", "quic", "dns", "capture_end", nil},
		{"broken.example.net", "Demo-iPhone", "", "dns", "rst", nil},
		{"updates.example.com", "Demo-Laptop", "tls", "sni", "fin", []string{"h2"}},
		{"time.example.com", "Demo-iPhone", "ntp", "dns", "capture_end", nil},
	}
	for _, tt := range tests {
		f, ok := flows[tt.host]
		if !ok {
			t.Errorf("%s: no flow_end event", tt.host)
			continue
		}
		if f.Device != tt.device || f.App != tt.app || f.HostSource != tt.source || f.Reason != tt.reason {
			t.Errorf("%s: device=%q app=%q source=%q reason=%q; want %q %q %q %q",
				tt.host, f.Device, f.App, f.HostSource, f.Reason, tt.device, tt.app, tt.source, tt.reason)
		}
		if !slices.Equal(f.ALPN, tt.alpn) {
			t.Errorf("%s: ALPN = %v, want %v", tt.host, f.ALPN, tt.alpn)
		}
	}

	web := flows["www.example.com"]
	if web.BytesIn < 42000 || web.BytesOut > web.BytesIn {
		t.Errorf("www.example.com: in %d / out %d bytes, want a ~45 KB download", web.BytesIn, web.BytesOut)
	}
	if trk := flows["tracker.example.org"]; trk.BytesOut <= trk.BytesIn {
		t.Errorf("tracker.example.org: out %d <= in %d, want an upload", trk.BytesOut, trk.BytesIn)
	}

	// The gateway answers DNS but never opens flows: it must not be a device.
	var devices []string
	for _, ev := range events {
		if ev.Kind == KindDevice {
			devices = append(devices, ev.Device.Label)
		}
	}
	if !slices.Equal(devices, []string{"Demo-iPhone", "Demo-Laptop"}) {
		t.Errorf("devices = %v", devices)
	}
	if stats.DNSResponses != 6 || stats.Devices != 2 || stats.DecodeErrors != 0 {
		t.Errorf("stats = %+v", stats)
	}
}

// Every flow must be reported as started once and ended once.
func TestEveryFlowStartsAndEndsOnce(t *testing.T) {
	events, _ := run(t, pcapgen.Sample().Frames)
	starts, ends := map[uint64]int{}, map[uint64]int{}
	for _, ev := range events {
		switch ev.Kind {
		case KindFlowStart:
			starts[ev.Flow.ID]++
		case KindFlowEnd:
			ends[ev.Flow.ID]++
		}
	}
	for id, n := range starts {
		if n != 1 || ends[id] != 1 {
			t.Errorf("flow %d: %d starts, %d ends", id, n, ends[id])
		}
	}
}

// The committed demo capture must keep working end to end through the file reader.
func TestSampleFile(t *testing.T) {
	src, err := capture.OpenFile(filepath.Join("..", "..", "testdata", "sample.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	var frames []pcapgen.Frame
	for {
		data, ci, err := src.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, pcapgen.Frame{Time: ci.Timestamp, Data: data})
	}
	if _, ok := ended(mustRun(t, frames))["www.example.com"]; !ok {
		t.Error("www.example.com not found in testdata/sample.pcap (regenerate with go run ./tools/gen-sample)")
	}
}

func mustRun(t *testing.T, frames []pcapgen.Frame) []Event {
	events, _ := run(t, frames)
	return events
}

// BenchmarkEngine measures end-to-end throughput over the sample session.
// Report it as packets per second: go test -bench Engine ./internal/engine
func BenchmarkEngine(b *testing.B) {
	frames := pcapgen.Sample().Frames
	var bytes int64
	for _, f := range frames {
		bytes += int64(len(f.Data))
	}
	b.SetBytes(bytes)
	b.ReportAllocs()
	for b.Loop() {
		e := New(layers.LinkTypeEthernet, Options{}, func(Event) {})
		for _, f := range frames {
			e.Process(f.Data, gopacket.CaptureInfo{Timestamp: f.Time, CaptureLength: len(f.Data), Length: len(f.Data)})
		}
		e.Close()
	}
	b.ReportMetric(float64(len(frames)*b.N)/b.Elapsed().Seconds(), "pkts/s")
}
