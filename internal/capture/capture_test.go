package capture

import (
	"net/netip"
	"testing"
)

var ifaces = []Interface{
	{Name: `\Device\NPF_{AAA}`, Description: "Intel(R) Wi-Fi 6 AX201 160MHz", Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.23")}},
	{Name: `\Device\NPF_{BBB}`, Description: "Microsoft Wi-Fi Direct Virtual Adapter #2", Addrs: []netip.Addr{
		netip.MustParseAddr("fe80::1"), netip.MustParseAddr("192.168.137.1"),
	}},
	{Name: `\Device\NPF_Loopback`, Description: "Adapter for loopback traffic capture"},
}

func TestFindHotspot(t *testing.T) {
	i, ok := FindHotspot(ifaces)
	if !ok || i.Name != `\Device\NPF_{BBB}` {
		t.Fatalf("FindHotspot = %v, %v", i.Name, ok)
	}
	if ip, _ := i.IPv4(); ip != HotspotGateway {
		t.Errorf("IPv4 = %v", ip)
	}
	if _, ok := FindHotspot(ifaces[:1]); ok {
		t.Error("found a hotspot where there is none")
	}
}

func TestFind(t *testing.T) {
	for query, want := range map[string]string{
		`\Device\NPF_{AAA}`: `\Device\NPF_{AAA}`,
		"wi-fi direct":      `\Device\NPF_{BBB}`,
		"loopback":          `\Device\NPF_Loopback`,
	} {
		i, err := Find(ifaces, query)
		if err != nil || i.Name != want {
			t.Errorf("Find(%q) = %q, %v; want %q", query, i.Name, err, want)
		}
	}
	if _, err := Find(ifaces, "adapter"); err == nil {
		t.Error(`Find("adapter") matched several interfaces without an error`)
	}
	if _, err := Find(ifaces, "ethernet"); err == nil {
		t.Error(`Find("ethernet") should fail`)
	}
}
