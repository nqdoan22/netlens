// Package output renders engine events for a terminal (human-readable lines)
// or for other programs (JSON Lines).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nqdoan22/netlens/internal/engine"
)

// JSON writes one JSON object per event.
type JSON struct {
	enc *json.Encoder
}

// NewJSON returns a JSON Lines writer.
func NewJSON(w io.Writer) *JSON { return &JSON{enc: json.NewEncoder(w)} }

// Write emits ev as one line of JSON.
func (j *JSON) Write(ev engine.Event) { _ = j.enc.Encode(ev) }

// Text prints events as aligned, human-readable lines:
//
//	14:02:11.532  DNS    Demo-iPhone       www.example.com A -> 203.0.113.10
//	14:02:11.540  OPEN   Demo-iPhone    -> www.example.com  [203.0.113.10:443 TCP tls h2]
//	14:02:13.910  CLOSE  Demo-iPhone    -> www.example.com  2.4s  out 1.9 KB  in 48.3 KB  (fin)
//
// Unless Verbose is set, local service chatter (DNS flows, mDNS, DHCP, SSDP,
// multicast/broadcast) is hidden: the DNS lines already show the lookups.
type Text struct {
	w       io.Writer
	Verbose bool
	opened  map[uint64]string // flow ID -> host shown in its OPEN line
}

// NewText returns a text printer.
func NewText(w io.Writer, verbose bool) *Text {
	return &Text{w: w, Verbose: verbose, opened: make(map[uint64]string)}
}

// Write prints ev.
func (t *Text) Write(ev engine.Event) {
	ts := ev.Time.Local().Format("15:04:05.000")
	switch ev.Kind {
	case engine.KindDevice:
		d := ev.Device
		fmt.Fprintf(t.w, "%s  DEVICE %-16s %s %s\n", ts, d.Label, d.IP, d.MAC)

	case engine.KindDNS:
		d := ev.DNS
		answers := strings.Join(d.Answers, ", ")
		if answers == "" {
			answers = d.RCode
		}
		fmt.Fprintf(t.w, "%s  DNS    %-16s    %s %s -> %s\n", ts, d.Device, d.Name, d.Type, answers)

	case engine.KindFlowStart:
		f := ev.Flow
		// TCP flows wait for classification (TLS/HTTP) so the line can say more.
		if f.Proto != "TCP" && t.visible(f) {
			t.open(ts, f)
		}

	case engine.KindFlowUpdate:
		f := ev.Flow
		if !t.visible(f) {
			return
		}
		shown, ok := t.opened[f.ID]
		switch {
		case !ok:
			t.open(ts, f)
		case f.Host != "" && f.Host != shown:
			fmt.Fprintf(t.w, "%s  HOST   %-16s -> %s (from %s)\n", ts, f.Device, f.Host, f.HostSource)
			t.opened[f.ID] = f.Host
		}

	case engine.KindFlowEnd:
		f := ev.Flow
		if !t.visible(f) {
			return
		}
		if _, ok := t.opened[f.ID]; !ok {
			t.open(ts, f)
		}
		delete(t.opened, f.ID)
		fmt.Fprintf(t.w, "%s  CLOSE  %-16s -> %s  %s  out %s  in %s  (%s)\n",
			ts, f.Device, dest(f), dur(f.DurationMs), Bytes(f.BytesOut), Bytes(f.BytesIn), f.Reason)
	}
}

func (t *Text) open(ts string, f *engine.FlowInfo) {
	t.opened[f.ID] = f.Host
	detail := []string{f.Server, f.Proto}
	if f.App != "" {
		detail = append(detail, f.App)
	}
	detail = append(detail, f.ALPN...)
	if f.ECH {
		detail = append(detail, "ECH")
	}
	fmt.Fprintf(t.w, "%s  OPEN   %-16s -> %s  [%s]\n", ts, f.Device, dest(f), strings.Join(detail, " "))
}

func (t *Text) visible(f *engine.FlowInfo) bool {
	if t.Verbose {
		return true
	}
	switch f.App {
	case "dns", "mdns", "dhcp", "ssdp", "llmnr", "netbios":
		return false
	}
	srv := f.ServerAddr()
	if srv.IsMulticast() || srv.IsUnspecified() || srv == broadcast {
		return false
	}
	return true
}

func dest(f *engine.FlowInfo) string {
	if f.Host != "" {
		return f.Host
	}
	return f.ServerAddr().String()
}

func dur(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

// Bytes formats a byte count with binary units.
func Bytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
