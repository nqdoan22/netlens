package proto

import (
	"bytes"
	"strings"
)

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
}

// HTTPRequest holds the parts of a clear-text HTTP/1.x request line and headers
// that identify the destination.
type HTTPRequest struct {
	Method string
	Path   string
	Host   string
}

// LooksLikeHTTP reports whether data starts with an HTTP/1.x request method.
func LooksLikeHTTP(data []byte) bool {
	for _, m := range httpMethods {
		if len(data) >= len(m) && bytes.Equal(data[:len(m)], m) {
			return true
		}
		if len(data) < len(m) && bytes.HasPrefix(m, data) {
			return true // could still become a method
		}
	}
	return false
}

// ParseHTTPRequest parses the request line and the Host header from the start
// of a clear-text HTTP/1.x request. It returns ErrNeedMore until the end of the
// header block is available.
func ParseHTTPRequest(data []byte) (*HTTPRequest, error) {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		if len(data) > 16<<10 {
			return nil, ErrMalformed
		}
		return nil, ErrNeedMore
	}
	lines := strings.Split(string(data[:end]), "\r\n")
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return nil, ErrMalformed
	}
	req := &HTTPRequest{Method: parts[0], Path: parts[1]}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			req.Host = stripPort(strings.TrimSpace(v))
			break
		}
	}
	return req, nil
}

func stripPort(host string) string {
	if strings.HasPrefix(host, "[") { // [v6]:port
		if i := strings.Index(host, "]"); i > 0 {
			return host[1:i]
		}
		return host
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.Count(host, ":") == 1 {
		return host[:i]
	}
	return host
}
