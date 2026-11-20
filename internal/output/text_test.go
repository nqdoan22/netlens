package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nqdoan22/netlens/internal/engine"
)

func TestBytes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 46648: "45.6 KB", 5 << 20: "5.0 MB"} {
		if got := Bytes(n); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestTextHidesLocalChatterUnlessVerbose(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mdns := &engine.FlowInfo{ID: 1, Device: "Demo-iPhone", Proto: "UDP", App: "mdns", Server: "224.0.0.251:5353"}
	web := &engine.FlowInfo{ID: 2, Device: "Demo-iPhone", Proto: "TCP", App: "tls", Host: "www.example.com", Server: "203.0.113.10:443"}
	events := []engine.Event{
		{Kind: engine.KindFlowStart, Time: at, Flow: mdns},
		{Kind: engine.KindFlowStart, Time: at, Flow: web},
		{Kind: engine.KindFlowUpdate, Time: at, Flow: web},
		{Kind: engine.KindFlowEnd, Time: at, Flow: web},
	}

	for _, verbose := range []bool{false, true} {
		var buf bytes.Buffer
		p := NewText(&buf, verbose)
		for _, ev := range events {
			p.Write(ev)
		}
		out := buf.String()
		if strings.Contains(out, "224.0.0.251") != verbose {
			t.Errorf("verbose=%v: mDNS shown = %v\n%s", verbose, !verbose, out)
		}
		if strings.Count(out, "OPEN") != 1+boolInt(verbose) || !strings.Contains(out, "CLOSE  Demo-iPhone      -> www.example.com") {
			t.Errorf("verbose=%v: unexpected output:\n%s", verbose, out)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
