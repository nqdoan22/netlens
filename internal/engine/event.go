package engine

import (
	"net/netip"
	"time"

	"github.com/nqdoan22/netlens/internal/device"
	"github.com/nqdoan22/netlens/internal/flow"
	"github.com/nqdoan22/netlens/internal/proto"
)

// Event kinds.
const (
	KindDevice     = "device"      // a new device appeared or its name was learned
	KindDNS        = "dns"         // a DNS response was seen
	KindFlowStart  = "flow_start"  // a new flow was opened
	KindFlowUpdate = "flow_update" // a flow was classified (TLS SNI, HTTP Host, ...)
	KindFlowEnd    = "flow_end"    // a flow ended
)

// Event is one observation reported by the Engine. Exactly one of Device, DNS
// or Flow is set, according to Kind. Events are snapshots and safe to keep.
type Event struct {
	Kind   string      `json:"event"`
	Time   time.Time   `json:"time"`
	Device *DeviceInfo `json:"device,omitempty"`
	DNS    *DNSInfo    `json:"dns,omitempty"`
	Flow   *FlowInfo   `json:"flow,omitempty"`
}

// DeviceInfo describes a local device.
type DeviceInfo struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Label    string `json:"label"`
}

// DNSInfo describes a DNS response.
type DNSInfo struct {
	Client  string   `json:"client"`
	Device  string   `json:"device"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	RCode   string   `json:"rcode"`
	Answers []string `json:"answers,omitempty"`
}

// FlowInfo describes a flow at the time of the event.
type FlowInfo struct {
	ID         uint64    `json:"id"`
	Device     string    `json:"device"`
	Proto      string    `json:"proto"`
	App        string    `json:"app,omitempty"`
	Host       string    `json:"host,omitempty"`
	HostSource string    `json:"host_source,omitempty"`
	ALPN       []string  `json:"alpn,omitempty"`
	ECH        bool      `json:"ech,omitempty"`
	Client     string    `json:"client"`
	Server     string    `json:"server"`
	Start      time.Time `json:"start"`
	DurationMs int64     `json:"duration_ms"`
	PktsOut    uint64    `json:"pkts_out"`
	PktsIn     uint64    `json:"pkts_in"`
	BytesOut   uint64    `json:"bytes_out"`
	BytesIn    uint64    `json:"bytes_in"`
	Reason     string    `json:"reason,omitempty"`
}

// ServerAddr returns the server endpoint's address.
func (f *FlowInfo) ServerAddr() netip.Addr {
	ap, err := netip.ParseAddrPort(f.Server)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr()
}

func deviceInfo(d *device.Device) *DeviceInfo {
	return &DeviceInfo{IP: d.IP.String(), MAC: d.MAC, Hostname: d.Hostname, Label: d.Label()}
}

func (e *Engine) dnsInfo(client netip.Addr, m *proto.DNSMessage) *DNSInfo {
	info := &DNSInfo{
		Client: client.String(),
		Device: e.deviceLabel(client),
		Name:   m.Name,
		Type:   m.Type,
		RCode:  m.RCode,
	}
	for _, a := range m.Answers {
		info.Answers = append(info.Answers, a.Addr.String())
	}
	return info
}

func (e *Engine) flowInfo(f *flow.Flow, reason flow.EndReason) *FlowInfo {
	return &FlowInfo{
		ID:         f.ID,
		Device:     e.deviceLabel(f.Client.Addr()),
		Proto:      f.Proto.String(),
		App:        f.App,
		Host:       f.Host,
		HostSource: f.HostSource,
		ALPN:       append([]string(nil), f.ALPN...),
		ECH:        f.ECH,
		Client:     f.Client.String(),
		Server:     f.Server.String(),
		Start:      f.Start,
		DurationMs: f.Duration().Milliseconds(),
		PktsOut:    f.PktsOut,
		PktsIn:     f.PktsIn,
		BytesOut:   f.BytesOut,
		BytesIn:    f.BytesIn,
		Reason:     string(reason),
	}
}
