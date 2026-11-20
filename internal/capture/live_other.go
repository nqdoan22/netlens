//go:build !windows && !linux

package capture

import (
	"errors"
	"runtime"
)

var errUnsupported = errors.New("live capture is not supported on " + runtime.GOOS + " yet; use -r to read a capture file")

// ListInterfaces is not implemented on this platform.
func ListInterfaces() ([]Interface, error) { return nil, errUnsupported }

// OpenLive is not implemented on this platform.
func OpenLive(string) (Source, error) { return nil, errUnsupported }
