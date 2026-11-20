// Package proto contains small, dependency-free parsers for the parts of
// application protocols NetLens can see in clear text: the TLS ClientHello,
// plain HTTP request headers, DNS and DHCP.
package proto

import (
	"errors"
)

// ClientHello holds the unencrypted fields of a TLS ClientHello that are useful
// for identifying where a connection goes and which client opened it.
type ClientHello struct {
	LegacyVersion     uint16
	SNI               string   // server_name extension (the destination host name)
	ALPN              []string // application protocols offered, e.g. "h2", "http/1.1"
	SupportedVersions []uint16 // supported_versions extension (TLS 1.3 clients)
	CipherSuites      []uint16
	Extensions        []uint16 // extension types in the order sent
	ECH               bool     // encrypted_client_hello present: SNI may be a decoy
}

var (
	// ErrNeedMore means the data is a plausible TLS ClientHello prefix but is
	// incomplete; call again once more bytes of the stream are available.
	ErrNeedMore = errors.New("tls: need more data")
	// ErrNotTLS means the data is not the start of a TLS handshake.
	ErrNotTLS = errors.New("tls: not a TLS handshake")
	// ErrNotClientHello means the first handshake message is not a ClientHello.
	ErrNotClientHello = errors.New("tls: first handshake message is not a ClientHello")
	// ErrMalformed means the ClientHello is complete but its contents are invalid.
	ErrMalformed = errors.New("tls: malformed ClientHello")
)

const (
	recordTypeHandshake   = 22
	handshakeClientHello  = 1
	recordHeaderLen       = 5
	handshakeHeaderLen    = 4
	maxClientHelloLen     = 1 << 16
	extServerName         = 0
	extALPN               = 16
	extSupportedVersions  = 43
	extEncryptedClientHel = 0xfe0d
)

// ParseClientHello parses the first bytes a client sends on a TLS connection.
//
// The ClientHello may be split over several TLS records and, because modern
// hellos carry large post-quantum key shares, over several TCP segments. data
// must therefore be the in-order start of the client→server byte stream; when it
// is too short, ParseClientHello returns ErrNeedMore.
func ParseClientHello(data []byte) (*ClientHello, error) {
	msg, err := reassembleHandshake(data)
	if err != nil {
		return nil, err
	}
	return parseClientHelloBody(msg)
}

// LooksLikeTLS reports whether data could be the start of a TLS handshake record.
// It is a cheap pre-check before buffering a stream for ParseClientHello.
func LooksLikeTLS(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if data[0] != recordTypeHandshake {
		return false
	}
	return len(data) < 2 || data[1] == 3 // record versions are 3.x
}

// reassembleHandshake joins the handshake fragments carried by consecutive
// records until the first handshake message is complete, and returns its body.
func reassembleHandshake(data []byte) ([]byte, error) {
	var hs []byte
	for {
		if len(data) == 0 {
			return nil, ErrNeedMore
		}
		if data[0] != recordTypeHandshake {
			return nil, ErrNotTLS
		}
		if len(data) < recordHeaderLen {
			return nil, ErrNeedMore
		}
		if data[1] != 3 {
			return nil, ErrNotTLS
		}
		recLen := int(data[3])<<8 | int(data[4])
		if recLen == 0 || recLen > 1<<14+2048 {
			return nil, ErrNotTLS
		}
		if len(data) < recordHeaderLen+recLen {
			// Use what we have so far to fail fast on a non-ClientHello.
			partial := append(hs, data[recordHeaderLen:]...)
			if len(partial) > 0 && partial[0] != handshakeClientHello {
				return nil, ErrNotClientHello
			}
			return nil, ErrNeedMore
		}
		hs = append(hs, data[recordHeaderLen:recordHeaderLen+recLen]...)
		data = data[recordHeaderLen+recLen:]

		if hs[0] != handshakeClientHello {
			return nil, ErrNotClientHello
		}
		if len(hs) < handshakeHeaderLen {
			continue
		}
		msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if msgLen > maxClientHelloLen {
			return nil, ErrMalformed
		}
		if len(hs) >= handshakeHeaderLen+msgLen {
			return hs[handshakeHeaderLen : handshakeHeaderLen+msgLen], nil
		}
	}
}

func parseClientHelloBody(b []byte) (*ClientHello, error) {
	r := reader(b)
	ch := &ClientHello{}
	var ok bool
	if ch.LegacyVersion, ok = r.u16(); !ok {
		return nil, ErrMalformed
	}
	if !r.skip(32) { // random
		return nil, ErrMalformed
	}
	if _, ok = r.vec8(); !ok { // legacy_session_id
		return nil, ErrMalformed
	}
	suites, ok := r.vec16()
	if !ok || len(suites)%2 != 0 {
		return nil, ErrMalformed
	}
	for i := 0; i+1 < len(suites); i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, uint16(suites[i])<<8|uint16(suites[i+1]))
	}
	if _, ok = r.vec8(); !ok { // legacy_compression_methods
		return nil, ErrMalformed
	}
	if len(r) == 0 {
		return ch, nil // very old clients may omit extensions entirely
	}
	exts, ok := r.vec16()
	if !ok {
		return nil, ErrMalformed
	}
	er := reader(exts)
	for len(er) > 0 {
		typ, ok1 := er.u16()
		body, ok2 := er.vec16()
		if !ok1 || !ok2 {
			return nil, ErrMalformed
		}
		ch.Extensions = append(ch.Extensions, typ)
		switch typ {
		case extServerName:
			ch.SNI = parseSNI(body)
		case extALPN:
			ch.ALPN = parseALPN(body)
		case extSupportedVersions:
			ch.SupportedVersions = parseVersions(body)
		case extEncryptedClientHel:
			ch.ECH = true
		}
	}
	return ch, nil
}

func parseSNI(b []byte) string {
	r := reader(b)
	list, ok := r.vec16()
	if !ok {
		return ""
	}
	lr := reader(list)
	for len(lr) > 0 {
		nameType, ok1 := lr.u8()
		name, ok2 := lr.vec16()
		if !ok1 || !ok2 {
			return ""
		}
		if nameType == 0 { // host_name
			return string(name)
		}
	}
	return ""
}

func parseALPN(b []byte) []string {
	r := reader(b)
	list, ok := r.vec16()
	if !ok {
		return nil
	}
	var out []string
	lr := reader(list)
	for len(lr) > 0 {
		p, ok := lr.vec8()
		if !ok {
			return out
		}
		out = append(out, string(p))
	}
	return out
}

func parseVersions(b []byte) []uint16 {
	r := reader(b)
	list, ok := r.vec8()
	if !ok || len(list)%2 != 0 {
		return nil
	}
	var out []uint16
	for i := 0; i+1 < len(list); i += 2 {
		out = append(out, uint16(list[i])<<8|uint16(list[i+1]))
	}
	return out
}

// IsGREASE reports whether v is a GREASE value (RFC 8701), which clients insert
// at random to keep servers tolerant and which fingerprints must ignore.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// reader is a minimal bounds-checked cursor over a byte slice.
type reader []byte

func (r *reader) u8() (uint8, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := (*r)[0]
	*r = (*r)[1:]
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := uint16((*r)[0])<<8 | uint16((*r)[1])
	*r = (*r)[2:]
	return v, true
}

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) vec8() ([]byte, bool) {
	n, ok := r.u8()
	if !ok {
		return nil, false
	}
	return r.bytes(int(n))
}

func (r *reader) vec16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	return r.bytes(int(n))
}
