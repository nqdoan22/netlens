# Architecture

## Deployment

NetLens runs on the machine that *routes* the monitored devices' traffic. In the
reference setup this is a Windows laptop with Mobile Hotspot turned on:

```text
 Phone (192.168.137.x) ──Wi-Fi──► Laptop ──Wi-Fi──► Home router ──► Internet
                                    │
           ┌────────────────────────┴───────────────────────┐
           │ Wi-Fi card, two roles at once                  │
           │  • station: connected to the home network      │
           │  • access point: "Microsoft Wi-Fi Direct       │
           │    Virtual Adapter" = the hotspot (192.168.137.1)
           │ Windows ICS: DHCP, DNS proxy, NAT              │
           │ NetLens: passive capture on the hotspot adapter│
           └────────────────────────────────────────────────┘
```

Windows does the routing; NetLens only reads copies of the frames (through
Npcap), so a crash or a stop never interrupts the devices' connectivity.

Capturing **on the hotspot side, before NAT**, is essential: after NAT every
packet carries the laptop's address and the devices can no longer be told apart.

## Pipeline

```text
capture.Source ──frames──► engine.Engine ──Events──► output (text / JSON)
  (reader goroutine)        (single goroutine)
                              │
       decode ── flow.Tracker ── proto parsers ── dnscache / device registry
```

| Package | Responsibility |
|---|---|
| `internal/capture` | packet sources: Npcap (Windows), AF_PACKET (Linux), pcap/pcapng files; hotspot adapter discovery |
| `internal/decode` | link → IP → TCP/UDP decoding with gopacket's `DecodingLayerParser` (no per-packet `gopacket.Packet` allocation) |
| `internal/flow` | bidirectional flows keyed by 5-tuple; client/server inference; TCP close and idle timeouts |
| `internal/proto` | dependency-free parsers: TLS ClientHello, HTTP/1.x request, DNS, DHCP |
| `internal/dnscache` | `(device, IP) → host name` from observed DNS answers |
| `internal/device` | local devices, named from DHCP |
| `internal/engine` | ties the above together and emits `Event`s |
| `internal/output` | terminal and JSON Lines renderers |
| `internal/pcapgen` | synthetic traffic for tests and the demo capture |

### Concurrency

One goroutine reads from the capture driver and hands frames to the analysis
goroutine over a buffered channel (8192 frames). The analysis side is
single-threaded by design: flow state needs no locks, and one core already
processes ~1.9 M packets/s, far above what a Wi-Fi hotspot carries. If the
consumer falls behind, the channel absorbs bursts; beyond that the driver drops
packets, which is reported in the summary.

### Naming a flow

A flow's host name comes from, in order of confidence:

1. **TLS SNI** or **HTTP Host**, read from the client's first bytes;
2. the **DNS answer** the same device received for the server's IP (per-device
   cache, falling back to any device, TTL stretched to at least 5 minutes).

The TLS ClientHello frequently spans several TCP segments (post-quantum key
shares make it ~1.5–2 KB). The engine buffers the in-order client byte stream —
up to 16 KB or 8 segments — and gives up on gaps rather than implementing full
TCP reassembly, because the hello is almost always at the very start of the
connection.

### Client / server inference

Captures can start mid-connection, so the first packet seen is not always from
the client. The tracker uses, in order: TCP SYN / SYN-ACK; local-vs-Internet
address (devices initiate); well-known service ports; higher ephemeral port.

### Flow lifecycle

- TCP flows end on RST, or once both sides sent FIN. The end is reported
  immediately; the entry then lingers 5 s to absorb the final ACKs.
- Other flows end after 60 s of silence (TCP: 5 min).
- Remaining flows are reported with reason `capture_end` when capture stops.

## Testing strategy

- Unit tests per package, table-driven.
- End-to-end tests run a synthetic session (`pcapgen.Sample`) through the
  engine, and the committed `testdata/sample.pcap` through the file reader.
- The TLS parser is fuzzed: it parses untrusted network bytes and must never panic.
- `BenchmarkEngine` tracks throughput in packets per second.
