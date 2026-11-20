package proto

import (
	"net/netip"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// DNSMessage is the summary of one DNS query or response.
type DNSMessage struct {
	ID       uint16
	Response bool
	Name     string // first question name, lower-case, without trailing dot
	Type     string // first question type, e.g. "A", "AAAA", "HTTPS"
	RCode    string // response code for responses, e.g. "NoError", "NXDomain"
	Answers  []DNSAnswer
}

// DNSAnswer is an address record from the answer section.
type DNSAnswer struct {
	Name string
	Addr netip.Addr
	TTL  time.Duration
}

// DNSParser decodes DNS messages. It reuses its internal layer between calls and
// is not safe for concurrent use.
type DNSParser struct {
	dns layers.DNS
}

// Parse decodes a DNS message carried over UDP.
func (p *DNSParser) Parse(payload []byte) (*DNSMessage, error) {
	if err := p.dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	d := &p.dns
	m := &DNSMessage{ID: d.ID, Response: d.QR}
	if len(d.Questions) > 0 {
		m.Name = normalizeName(string(d.Questions[0].Name))
		m.Type = d.Questions[0].Type.String()
	}
	if d.QR {
		m.RCode = d.ResponseCode.String()
	}
	for _, rr := range d.Answers {
		if rr.Type != layers.DNSTypeA && rr.Type != layers.DNSTypeAAAA {
			continue
		}
		addr, ok := netip.AddrFromSlice(rr.IP)
		if !ok {
			continue
		}
		m.Answers = append(m.Answers, DNSAnswer{
			Name: normalizeName(string(rr.Name)),
			Addr: addr.Unmap(),
			TTL:  time.Duration(rr.TTL) * time.Second,
		})
	}
	return m, nil
}

func normalizeName(n string) string {
	return strings.ToLower(strings.TrimSuffix(n, "."))
}
