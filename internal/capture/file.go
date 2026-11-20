package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

type fileSource struct {
	f *os.File
	r packetReader
}

// pcapng files start with a Section Header Block.
var pcapngMagic = []byte{0x0a, 0x0d, 0x0d, 0x0a}

// OpenFile opens a pcap or pcapng file (as written by Wireshark or tcpdump).
func OpenFile(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: not a capture file: %w", path, err)
	}
	var r packetReader
	if bytes.Equal(magic, pcapngMagic) {
		r, err = pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
	} else {
		r, err = pcapgo.NewReader(br)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &fileSource{f: f, r: r}, nil
}

func (s *fileSource) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	return s.r.ReadPacketData()
}

func (s *fileSource) LinkType() layers.LinkType { return s.r.LinkType() }
func (s *fileSource) Dropped() (uint64, bool)   { return 0, false }
func (s *fileSource) Close() error              { return s.f.Close() }
