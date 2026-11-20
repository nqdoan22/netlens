package proto

import (
	"errors"
	"slices"
	"testing"

	"github.com/nqdoan22/netlens/internal/pcapgen"
)

func TestParseClientHelloFromRealClient(t *testing.T) {
	hello := pcapgen.ClientHello("www.example.com", "h2", "http/1.1")
	ch, err := ParseClientHello(hello)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.SNI != "www.example.com" {
		t.Errorf("SNI = %q, want www.example.com", ch.SNI)
	}
	if !slices.Equal(ch.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %v", ch.ALPN)
	}
	if !slices.Contains(ch.SupportedVersions, 0x0304) {
		t.Errorf("SupportedVersions = %x, want TLS 1.3 (0x0304)", ch.SupportedVersions)
	}
	if len(ch.CipherSuites) == 0 || len(ch.Extensions) == 0 {
		t.Errorf("cipher suites %d, extensions %d: want both non-empty", len(ch.CipherSuites), len(ch.Extensions))
	}
}

// Every proper prefix of a ClientHello must ask for more data, never fail:
// the engine feeds the parser one TCP segment at a time.
func TestParseClientHelloPrefixes(t *testing.T) {
	hello := pcapgen.ClientHello("prefix.example.com")
	for n := 0; n < len(hello); n++ {
		if _, err := ParseClientHello(hello[:n]); !errors.Is(err, ErrNeedMore) {
			t.Fatalf("prefix of %d/%d bytes: err = %v, want ErrNeedMore", n, len(hello), err)
		}
	}
}

// A handshake message may be fragmented across several TLS records.
func TestParseClientHelloAcrossRecords(t *testing.T) {
	hello := pcapgen.ClientHello("split.example.com")
	body := hello[5:]
	cut := len(body) / 3
	var split []byte
	for _, frag := range [][]byte{body[:cut], body[cut:]} {
		split = append(split, 22, 3, 1, byte(len(frag)>>8), byte(len(frag)))
		split = append(split, frag...)
	}
	ch, err := ParseClientHello(split)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.SNI != "split.example.com" {
		t.Errorf("SNI = %q", ch.SNI)
	}
}

func TestParseClientHelloRejects(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"http", []byte("GET / HTTP/1.1\r\n\r\n"), ErrNotTLS},
		{"application data record", []byte{23, 3, 3, 0, 5, 1, 2, 3, 4, 5}, ErrNotTLS},
		{"bad record version", []byte{22, 9, 9, 0, 5, 1, 0, 0, 1, 0}, ErrNotTLS},
		{"server hello", []byte{22, 3, 3, 0, 4, 2, 0, 0, 0}, ErrNotClientHello},
		{"truncated body", []byte{22, 3, 1, 0, 6, 1, 0, 0, 2, 3, 3}, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseClientHello(tt.data); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = false", v)
		}
	}
	for _, v := range []uint16{0x0a1a, 0x1301, 0x0000} {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = true", v)
		}
	}
}

// The parser reads untrusted bytes off the network: it must never panic.
func FuzzParseClientHello(f *testing.F) {
	f.Add(pcapgen.ClientHello("fuzz.example.com", "h2"))
	f.Add([]byte{22, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseClientHello(data)
	})
}

func BenchmarkParseClientHello(b *testing.B) {
	hello := pcapgen.ClientHello("bench.example.com", "h2", "http/1.1")
	b.SetBytes(int64(len(hello)))
	for b.Loop() {
		if _, err := ParseClientHello(hello); err != nil {
			b.Fatal(err)
		}
	}
}
