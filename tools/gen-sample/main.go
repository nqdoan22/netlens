// Command gen-sample writes testdata/sample.pcap, a synthetic capture used for
// demos and end-to-end tests. Run it from the repository root:
//
//	go run ./tools/gen-sample
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nqdoan22/netlens/internal/pcapgen"
)

func main() {
	out := flag.String("o", "testdata/sample.pcap", "output file")
	flag.Parse()

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b := pcapgen.Sample()
	if err := b.WritePcap(f); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d packets to %s\n", len(b.Frames), *out)
}
