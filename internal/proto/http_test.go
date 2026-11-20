package proto

import (
	"errors"
	"testing"
)

func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantErr  error
	}{
		{"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", nil},
		{"POST /x HTTP/1.0\r\nhost:  example.com:8080 \r\nX: y\r\n\r\nbody", "example.com", nil},
		{"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", "2001:db8::1", nil},
		{"GET / HTTP/1.1\r\nHost: exa", "", ErrNeedMore},
		{"GET / SPDY/3\r\n\r\n", "", ErrMalformed},
	}
	for _, tt := range tests {
		req, err := ParseHTTPRequest([]byte(tt.in))
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%q: err = %v, want %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && req.Host != tt.wantHost {
			t.Errorf("%q: Host = %q, want %q", tt.in, req.Host, tt.wantHost)
		}
	}
}

func TestLooksLikeHTTP(t *testing.T) {
	for in, want := range map[string]bool{
		"GET / HTTP/1.1": true,
		"PO":             true, // could still become POST
		"\x16\x03\x01":   false,
		"SSH-2.0-":       false,
	} {
		if got := LooksLikeHTTP([]byte(in)); got != want {
			t.Errorf("LooksLikeHTTP(%q) = %v, want %v", in, got, want)
		}
	}
}
