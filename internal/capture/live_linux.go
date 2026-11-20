//go:build linux

package capture

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

// On Linux, live capture uses AF_PACKET sockets with a memory-mapped ring
// (TPACKET_V3). It needs root or the CAP_NET_RAW capability.

// ListInterfaces returns the system's network interfaces.
func ListInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, ni := range ifs {
		i := Interface{Name: ni.Name, Description: ni.HardwareAddr.String()}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			if pfx, err := netip.ParsePrefix(a.String()); err == nil {
				i.Addrs = append(i.Addrs, pfx.Addr())
			}
		}
		out = append(out, i)
	}
	return out, nil
}

type liveSource struct {
	tp *afpacket.TPacket
}

// OpenLive starts capturing on the named interface.
func OpenLive(name string) (Source, error) {
	tp, err := afpacket.NewTPacket(
		afpacket.OptInterface(name),
		afpacket.OptPollTimeout(250*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w (live capture needs root or CAP_NET_RAW)", name, err)
	}
	return &liveSource{tp: tp}, nil
}

func (s *liveSource) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := s.tp.ReadPacketData()
	if err == afpacket.ErrTimeout {
		return nil, ci, ErrTimeout
	}
	return data, ci, err
}

func (s *liveSource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

func (s *liveSource) Dropped() (uint64, bool) {
	_, st, err := s.tp.SocketStats()
	if err != nil {
		return 0, false
	}
	return uint64(st.Drops()), true
}

func (s *liveSource) Close() error {
	s.tp.Close()
	return nil
}
