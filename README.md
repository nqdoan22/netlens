# NetLens

**See which servers the devices on your network talk to — without installing anything on them.**

NetLens turns a Windows laptop into a transparent observation point. Turn on the
laptop's Mobile Hotspot, connect a phone (or any device) to it, and NetLens
reports in real time which hosts the device connects to, over which protocol,
and how much data goes each way.

```text
09:30:00.000  DEVICE Demo-iPhone      192.168.137.45 02:00:00:00:00:45
09:30:00.218  DNS    Demo-iPhone         www.example.com A -> 203.0.113.10
09:30:00.224  OPEN   Demo-iPhone      -> www.example.com  [203.0.113.10:443 TCP tls h2 http/1.1]
09:30:02.259  CLOSE  Demo-iPhone      -> www.example.com  2.0s  out 2.0 KB  in 45.6 KB  (fin)
09:30:02.265  OPEN   Demo-iPhone      -> tracker.example.org  [192.0.2.50:443 TCP tls http/1.1]
09:30:02.771  CLOSE  Demo-iPhone      -> tracker.example.org  510ms  out 4.9 KB  in 774 B  (fin)
09:30:02.815  OPEN   Demo-iPhone      -> video.example.com  [198.51.100.30:443 UDP quic]
```

*(Output of `netlens -r testdata/sample.pcap`, a synthetic capture shipped with the repository.)*

## How it works

```text
 Phone ──Wi-Fi──► [ Laptop: Mobile Hotspot ] ──Wi-Fi──► Home router ──► Internet
                         │
                  NetLens captures here, on the hotspot adapter,
                  before NAT hides which device sent each packet
```

NetLens never decrypts traffic. It reads the metadata every network can see:

| Signal | What it reveals |
|---|---|
| **DNS** queries and answers | which host name a device resolved before connecting |
| **TLS ClientHello** (SNI, ALPN) | the host name of an HTTPS connection, reassembled across TCP segments |
| **HTTP/1.x** request headers | the `Host` of clear-text web requests |
| **DHCP** requests | the device's name, e.g. `Johns-iPhone` |
| Flow accounting | packets and bytes per direction, duration, how the connection ended |

Packets go through a small pipeline: **capture → decode → flow tracking →
protocol analysis → events**. See [docs/architecture.md](docs/architecture.md)
for the design.

## Quick start (Windows)

1. Install [Npcap](https://npcap.com) (keep *WinPcap API-compatible mode* checked).
2. Turn on **Settings → Network & internet → Mobile hotspot** and connect your phone to it.
3. Run in a terminal:

   ```powershell
   netlens.exe -list     # the hotspot adapter is marked with *
   netlens.exe           # capture on the hotspot (-i auto)
   ```

A step-by-step guide in Vietnamese, including the iPhone settings that matter, is in
[docs/getting-started.vi.md](docs/getting-started.vi.md).

Try it without a hotspot on the bundled capture:

```bash
go run ./cmd/netlens -r testdata/sample.pcap
go run ./cmd/netlens -r testdata/sample.pcap -json   # JSON Lines for other tools
```

### Flags

| Flag | Meaning |
|---|---|
| `-i auto\|<name>` | interface to capture from; `auto` picks the Windows Mobile Hotspot adapter |
| `-r file` | analyze a pcap/pcapng file (e.g. saved by Wireshark) instead of capturing |
| `-list` | list interfaces |
| `-json` | print events as JSON Lines |
| `-v` | also show local service traffic (DNS, mDNS, DHCP, multicast) |
| `-gateway ip` | this machine's address on the monitored network (excluded from devices) |

Live capture is supported on Windows (Npcap) and Linux (AF_PACKET, needs root or
`CAP_NET_RAW`); any platform can read capture files.

## Building

Requires Go 1.25+. No cgo: Windows binaries cross-compile from any OS.

```bash
go build ./cmd/netlens                                    # current platform
GOOS=windows GOARCH=amd64 go build -o netlens.exe ./cmd/netlens
GOOS=linux GOARCH=arm64 go build ./cmd/netlens            # e.g. Raspberry Pi
```

## Testing

```bash
go test -race ./...                                       # unit and end-to-end tests
go test -run '^$' -fuzz FuzzParseClientHello ./internal/proto   # fuzz the TLS parser
go test -run '^$' -bench . ./internal/engine              # throughput
go run ./tools/gen-sample                                 # regenerate testdata/sample.pcap
```

Tests run on synthetic traffic built by [`internal/pcapgen`](internal/pcapgen):
documentation-range addresses (RFC 5737), reserved domains (RFC 2606) and real
ClientHellos produced by Go's `crypto/tls`. **Never commit real captures**: they
contain your personal traffic.

The analysis engine processes about **1.9 million packets per second on one CPU
core** on the sample session (Xeon 2.1 GHz, `BenchmarkEngine`).

## Limits

- HTTPS **content** is not visible, by design: NetLens sees where a device
  connects, not what it says.
- Apps that use encrypted DNS (DoH) or Encrypted Client Hello hide host names;
  such flows are shown by IP address.
- Traffic that does not cross the hotspot (a phone falling back to mobile data,
  iCloud Private Relay) cannot be seen.
- QUIC flows are named from DNS for now; reading the SNI from QUIC Initial
  packets is on the roadmap.

## Roadmap

- [x] **M1** — capture, flow tracking, DNS / TLS SNI / HTTP / DHCP analysis, CLI
- [ ] **M2** — SQLite storage, REST + WebSocket API, live web dashboard
- [ ] **M3** — GeoIP/ASN, tracker lists, QUIC SNI, JA4 fingerprints, alerts (new domains, beaconing)
- [ ] **M4** — blocking by domain or device (WinDivert), optional HTTPS inspection
- [ ] **M5** — performance report, packaging, v1.0

## Responsible use

Monitor only networks and devices you own, or whose users have agreed to it.
NetLens is meant to understand your own devices' behavior; it does not and will
not include features for intercepting other people's traffic (e.g. ARP spoofing).

## License

[MIT](LICENSE)
