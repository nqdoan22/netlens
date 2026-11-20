//go:build windows

package capture

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// On Windows, live capture goes through Npcap (https://npcap.com). gopacket
// loads wpcap.dll at run time, so the binary builds without cgo, but Npcap must
// be installed on the machine that runs it.

const npcapHint = "is Npcap installed? Download it from https://npcap.com (keep \"WinPcap API-compatible mode\" enabled)"

// ListInterfaces returns the interfaces Npcap can capture from.
func ListInterfaces() ([]Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w (%s)", err, npcapHint)
	}
	out := make([]Interface, 0, len(devs))
	for _, d := range devs {
		i := Interface{Name: d.Name, Description: d.Description}
		for _, a := range d.Addresses {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				i.Addrs = append(i.Addrs, ip.Unmap())
			}
		}
		out = append(out, i)
	}
	return out, nil
}

type liveSource struct {
	h *pcap.Handle
}

// OpenLive starts capturing on the named interface.
func OpenLive(name string) (Source, error) {
	// Not promiscuous: on a hotspot every frame is addressed to us anyway.
	// The short timeout lets the reader notice shutdown requests.
	h, err := pcap.OpenLive(name, 65535, false, 250*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w (%s)", name, err, npcapHint)
	}
	return &liveSource{h: h}, nil
}

func (s *liveSource) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := s.h.ReadPacketData()
	if err == pcap.NextErrorTimeoutExpired {
		return nil, ci, ErrTimeout
	}
	return data, ci, err
}

func (s *liveSource) LinkType() layers.LinkType { return s.h.LinkType() }

func (s *liveSource) Dropped() (uint64, bool) {
	st, err := s.h.Stats()
	if err != nil {
		return 0, false
	}
	return uint64(st.PacketsDropped + st.PacketsIfDropped), true
}

func (s *liveSource) Close() error {
	s.h.Close()
	return nil
}
