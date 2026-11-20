// Command netlens watches the traffic of devices connected to a monitored
// network (typically a Windows Mobile Hotspot) and reports, per device, which
// hosts they talk to, over which protocol, and how much data they exchange.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/nqdoan22/netlens/internal/capture"
	"github.com/nqdoan22/netlens/internal/engine"
	"github.com/nqdoan22/netlens/internal/output"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "netlens:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		iface    = flag.String("i", "auto", `interface to capture from: a name or description from -list, or "auto" for the Windows Mobile Hotspot adapter`)
		file     = flag.String("r", "", "read packets from a pcap/pcapng file instead of capturing live")
		list     = flag.Bool("list", false, "list capturable interfaces and exit")
		jsonOut  = flag.Bool("json", false, "print events as JSON Lines")
		verbose  = flag.Bool("v", false, "also show local service traffic (DNS, mDNS, DHCP, multicast)")
		gateway  = flag.String("gateway", "", "address of this machine on the monitored network, not reported as a device (default: the capture interface's IPv4 address, or 192.168.137.1 for files)")
		showVers = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	switch {
	case *showVers:
		fmt.Println("netlens", version)
		return nil
	case *list:
		return listInterfaces()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	src, gw, err := openSource(*file, *iface)
	if err != nil {
		return err
	}
	defer src.Close()
	switch {
	case *gateway != "":
		if gw, err = netip.ParseAddr(*gateway); err != nil {
			return fmt.Errorf("-gateway: %w", err)
		}
	case !gw.IsValid():
		gw = capture.HotspotGateway // capture files are usually recorded on the hotspot
	}

	var out io.Writer = os.Stdout
	flush := func() error { return nil }
	if *file != "" { // replaying a file: buffer output, nobody is watching it live
		bw := bufio.NewWriterSize(os.Stdout, 64<<10)
		out, flush = bw, bw.Flush
	}
	var write func(engine.Event)
	if *jsonOut {
		write = output.NewJSON(out).Write
	} else {
		write = output.NewText(out, *verbose).Write
	}

	eng := engine.New(src.LinkType(), engine.Options{Gateway: gw}, write)
	start := time.Now()
	err = pump(ctx, src, eng, *file == "")
	eng.Close()
	if ferr := flush(); err == nil {
		err = ferr
	}
	printSummary(eng.Stats(), src, time.Since(start))
	return err
}

func usage() {
	fmt.Fprint(os.Stderr, `NetLens: see which hosts the devices on your network talk to.

Usage:
  netlens [-i auto|<interface>] [-json] [-v]   capture live (needs Npcap on Windows)
  netlens -r capture.pcapng [-json] [-v]       analyze a capture file
  netlens -list                                list interfaces

Flags:
`)
	flag.PrintDefaults()
}

func listInterfaces() error {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		return err
	}
	hotspot, hasHotspot := capture.FindHotspot(ifaces)
	for _, i := range ifaces {
		mark := "  "
		if hasHotspot && i.Name == hotspot.Name {
			mark = "* "
		}
		addrs := make([]string, len(i.Addrs))
		for k, a := range i.Addrs {
			addrs[k] = a.String()
		}
		fmt.Printf("%s%s\n    %s\n    %s\n", mark, i.Name, i.Description, strings.Join(addrs, ", "))
	}
	if hasHotspot {
		fmt.Println("\n* Windows Mobile Hotspot adapter: used by -i auto")
	} else {
		fmt.Println("\nNo Windows Mobile Hotspot adapter found (turn on Mobile hotspot to use -i auto).")
	}
	return nil
}

// openSource opens the capture file or live interface and returns the address
// of this machine on the captured network, if known.
func openSource(file, iface string) (capture.Source, netip.Addr, error) {
	if file != "" {
		src, err := capture.OpenFile(file)
		return src, netip.Addr{}, err
	}
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	var target capture.Interface
	if iface == "auto" {
		var ok bool
		if target, ok = capture.FindHotspot(ifaces); !ok {
			return nil, netip.Addr{}, errors.New("no Windows Mobile Hotspot adapter found: turn on Settings > Network & internet > Mobile hotspot, or pick an interface with -i (see -list)")
		}
	} else if target, err = capture.Find(ifaces, iface); err != nil {
		return nil, netip.Addr{}, err
	}
	src, err := capture.OpenLive(target.Name)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	gw, _ := target.IPv4()
	fmt.Fprintf(os.Stderr, "Capturing on %s (%s). Press Ctrl+C to stop.\n", target.Description, target.Name)
	return src, gw, nil
}

type frame struct {
	data []byte
	ci   gopacket.CaptureInfo
}

// pump reads frames on one goroutine and analyzes them on the caller's, so a
// slow consumer (e.g. a terminal) does not stall the capture driver's buffer.
func pump(ctx context.Context, src capture.Source, eng *engine.Engine, live bool) error {
	frames := make(chan frame, 8192)
	readErr := make(chan error, 1)
	go func() {
		var err error
		defer func() {
			readErr <- err // sent before close so the consumer always receives it
			close(frames)
		}()
		for ctx.Err() == nil {
			var fr frame
			fr.data, fr.ci, err = src.ReadPacket()
			switch {
			case errors.Is(err, capture.ErrTimeout):
				err = nil
				continue
			case errors.Is(err, io.EOF):
				err = nil
				return
			case err != nil:
				return
			}
			select {
			case frames <- fr:
			case <-ctx.Done():
				return
			}
		}
	}()

	var tick <-chan time.Time
	if live {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case fr, ok := <-frames:
			if !ok {
				return <-readErr
			}
			eng.Process(fr.data, fr.ci)
		case now := <-tick:
			eng.Tick(now)
		}
	}
}

func printSummary(s engine.Stats, src capture.Source, elapsed time.Duration) {
	fmt.Fprintf(os.Stderr, "\n%d packets (%s), %d flows, %d DNS responses, %d devices in %s",
		s.Packets, output.Bytes(s.Bytes), s.Flows, s.DNSResponses, s.Devices, elapsed.Round(time.Millisecond))
	if dropped, ok := src.Dropped(); ok {
		fmt.Fprintf(os.Stderr, ", %d dropped by capture", dropped)
	}
	if s.DecodeErrors > 0 {
		fmt.Fprintf(os.Stderr, ", %d undecodable", s.DecodeErrors)
	}
	fmt.Fprintln(os.Stderr)
}
