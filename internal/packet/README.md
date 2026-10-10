<!-- Carrier reconstruction by ir_spoof; https://t.me/ir_spoof. -->

# Linux opaque packet carriers

This package provides IPv4 datagram codecs and a Linux `net.PacketConn` adapter.
The caller supplies the inner payload. It does not invent KCP, L3, TUN, peer
authentication, or encryption framing. The reference binary uses Ethernet,
IPv4 and TCP-shaped rawsocket packets. Its recovered envelope and sequence
progression and recovered constructor defaults are available through the
explicit `RawTCP` option. Runtime interoperability evidence belongs in the release
compatibility report. Generic codec tests alone do not establish carrier compatibility.

The independently written implementation is attributed to `ir_spoof`. The
behavioral reference remains [Karrari-Dev/Netrix-](https://github.com/Karrari-Dev/Netrix-).

## API

```go
codec, err := packet.NewCodec(options)
conn, err := packet.Listen(options) // Linux only; returns net.PacketConn
```

`Codec.Encode(payload, packetID)` emits a checksummed IPv4 datagram.
`Codec.Decode(frame)` verifies headers, checksums, MTU and configured peer
admission, returning a payload slice that aliases the supplied frame.
`Codec.PayloadMTU()` gives the maximum inner datagram size. Convenience
functions `EncodeIPv4`, `DecodeIPv4`, `EncodeEthernet` and `DecodeEthernet`
support offline fixtures. `ParseTCPFlags` maps usual TCP flag names or short
letters to their byte mask; `ParseTCPFlagCycle` preserves separate mask entries.
`PeerAddr(options)` returns a copied logical UDP-shaped peer address. These
helpers do not open sockets.

Options use literal unicast IPv4 addresses. `LocalIP` and `PeerIP` identify the
logical peers. `SpoofSrcIP` and `SpoofDstIP` replace the outgoing wire addresses.
`ReceiveSrcIP` and `ReceiveDstIP` optionally specify the opposite peer's wire
addresses; their defaults are `PeerIP` and `LocalIP`. Transmit spoof addresses
cannot safely infer a peer's receive admission settings. All addresses and
optional byte settings are copied so caller mutation cannot alter a live
filter. This is the generic packet API: the L3 adapter interprets `spoof_dst_ip`
as the expected incoming source and still transmits to the real peer. IPv6 outer
headers and automatic peer discovery are unsupported.

TCP and UDP carriers require `LocalPort` and `PeerPort`. A RawTCP listener may
explicitly set `PeerPortAny=true` with `PeerPort=0`; its peer IP remains fixed,
`ReadFrom` returns the validated TCP source port, and replies use that address.
`DecodePeer` exposes the same metadata for offline decoding. Other carriers
and fixed-peer sockets do not implicitly admit arbitrary ports. TCP shaped datagrams
also use `LocalFlags` for outgoing flags and `RemoteFlags` for exact receive
admission. An ICMP carrier uses an eight-byte standard ICMP header, configured
type/code, a local-port identifier by default, and packet-ID sequence. Optional
`ICMPIdentifier` overrides that identifier for both encoding and admission; its
pointed-to value is copied at codec creation. L3 uses the recovered folded SID
identifier, independently of ports. Optional
`PeerICMPType`/`PeerICMPCode` admit different peer values. These are standard
header choices, not recovered proprietary inner payload formats.

## Carrier I/O

| Carrier | Socket behavior |
| --- | --- |
| `udp` | Ordinary `udp4` socket when no spoofing or Ethernet override is configured |
| `raw` | `AF_INET/SOCK_RAW`, explicit IPv4 protocol, `IP_HDRINCL` |
| `icmp` | `AF_INET/SOCK_RAW`, ICMP protocol, `IP_HDRINCL` |
| Spoofed `udp` | Raw IPv4 socket carrying a complete checksummed UDP header |
| `tcp` | `AF_PACKET` Ethernet socket carrying TCP-shaped datagrams |
| `pcap` | `AF_PACKET` Ethernet socket carrying opaque raw-IP payload; no libpcap dependency |
| Explicit `AFPacket` | Ethernet-layer I/O for the selected codec |

Raw protocol defaults to experimental-use protocol 253. The MTU defaults to
1,500 and includes the IPv4 and optional transport headers. TCP shaping is not
a TCP stream, handshake, acknowledgement engine or congestion-control system.
The generic TCP codec emits a conventional 20-byte TCP header with
packet-ID-derived sequence and zero acknowledgement. The reference L3 `tcp`
carrier is an actual TCP stream; this shaped codec must not substitute for it.

For recovered rawsocket framing, use `Carrier="tcp", RawTCP=true`. Its TCP
payload is an eight-byte prefix followed by opaque KCP data: four zero bytes,
a little-endian 16-bit data length at bytes 4–5, and two reserved bytes. The
reader bounds the nonzero length and ignores the other prefix bytes, matching
the recovered reference behavior. Payload MTU is total IPv4 MTU minus 48 bytes.
At a 1,500-byte IPv4 MTU, KCP data up to 1,452 bytes fits. Reference rawsocket
configuration's MTU must be interpreted separately from total-IP MTU; its core
subtracts transport overhead before setting the KCP MTU.

RawTCP sends a 20-byte IPv4 header with TTL 64, protocol 6, no fragment flags,
and a monotonically incremented global packet ID. Its TCP header has no
options and window 65,535. `TCPSequence` and `TCPAck` supply initial caller
state; zero options select the recovered constructor's initial value of one.
Sequence advances by the opaque data length plus eight. A local flag
cycle chooses `cycle[sequence % len(cycle)]`, defaulting to `[PA,A]` for clients
and `[PA]` for the explicit listener wildcard. An explicit
remote flag cycle admits its listed masks; an absent one does not add a flag
constraint beyond peer/header checks, admitting the peer's PA/A default masks.
The reference client chooses a source port in 1,024–51,023; its listener uses
the configured endpoint port and creates a virtual connection for each source
port. Listener transmit sequence state is independently scoped to each peer
source port during that listener's lifetime. This library leaves port assignment
to the caller.

Raw and Ethernet sockets require `CAP_NET_RAW` or equivalent privileges. An
Ethernet socket requires an explicit active interface with a six-byte hardware
address and sufficient MTU, plus a unicast `RouterMAC` next hop.
If the MAC is absent, `ResolveRouterMAC` reads the explicit interface's local
route/neighbor state with a trusted `ip` helper and sends at most three ARP
requests over three seconds for the selected on-link next hop. An explicit MAC
avoids this discovery. No public-IP lookup, DNS discovery or firewall rule is
generated. Spoofed addresses must still be routable
or deliverable in the caller's controlled environment. A receive destination
that differs from the assigned local address requires Ethernet reception and
an explicit next-hop MAC.

Each raw/Ethernet descriptor has an owned generated classic-BPF filter that
admits only its configured source/destination IPv4 addresses, protocol and
optional ports, ICMP type/code or TCP flags. The filter disappears with the
socket and does not alter shared host filtering. The current live Ethernet
filter admits untagged IPv4 frames; the offline Ethernet decoder additionally
accepts up to two VLAN tags. `PcapSnaplen` bounds capture to 68–262,144 bytes;
smaller than a full packet intentionally truncates it, so it cannot decode.
`PcapPollMs` bounds read polling to 0–60,000 milliseconds (zero uses the normal
deadline wait). `PcapPromisc` enables descriptor-owned `PACKET_MR_PROMISC`
membership, automatically removed on close, while fixed peer admission remains.
These capture settings require Ethernet I/O.

`PcapFilter` is an additional predicate, never a replacement for fixed-peer
admission. Expressions up to 4,096 bytes compile offline through trusted system
libpcap's `pcap_compile_nopcap` via purego, or a root-owned `tcpdump -ddd` helper
reading a synthetic pcap header on stdin. No capture is opened by a compiler.
Library/executable paths and their parents must be root-owned and not writable
by other users; compiler output and execution time are bounded. A missing helper
or invalid expression fails explicitly. The compiled condition is combined with
the owned BPF filter using logical AND. Default packet I/O does not require
libpcap. The purego build's ELF runtime requirements are recorded in the release
README; `CGO_ENABLED=0` alone is not evidence of a fully static executable.

## Lifecycle and bounds

Reads drop malformed and unconfigured frames without publishing their payload.
IPv4 header options and TCP options are parsed with bounded lengths. IPv4
reserved fragment flags, invalid transport checksums and incorrect
peer addresses/ports/flags are rejected. IPv4 UDP's permitted zero checksum is
accepted; transmitted UDP packets always have a checksum. Ethernet padding
outside the IPv4 total length is ignored.

`AllowIPFragments` explicitly enables IPv4 fragmentation for raw-IP and ICMP
carriers and clears DF; it is rejected for UDP/TCP, which retain their documented
behavior. `PayloadMTU` remains the per-packet path budget; `MaxPayload` permits
a bounded complete IPv4 datagram. Oversized sends split into at most 128 parts
at the configured MTU, with shared packet ID and checksummed eight-byte offsets.
Receives reassemble only the configured wire peer/protocol, rejecting conflicting
overlaps and invalid checksums. State is limited to 32 flows, 128 parts per flow,
one MiB aggregate data and a five-second lifetime. Completed transport checksums
are verified before any payload is exposed. Fragment sends can partially reach
the peer before a later send error; higher-layer retries remain the caller's job.
Fragmentation is disabled by default.

`WriteTo` accepts only the configured logical `*net.UDPAddr` peer. The explicit
RawTCP listener wildcard permits nonzero ports on that configured IP, allowing
replies without permitting arbitrary destination IPs. Returned peer addresses
are copies. An undersized `ReadFrom` buffer truncates that one datagram, following
the ordinary `net.PacketConn` convention. Callers should allocate at least the
payload MTU and implement any required higher-layer fragmentation themselves.

Raw sockets are nonblocking. Independent event descriptors wake read and write
polling when deadlines change or the connection closes. Close waits for active
operations before closing descriptors, avoiding a syscall on a recycled file
descriptor. Deadline errors wrap `os.ErrDeadlineExceeded`; closed operations
wrap `net.ErrClosed`. No packet contents or addresses are written to disk.

## Validation

Portable tests cover independently serialized/checksummed IPv4, ICMP, UDP and
TCP fixtures; checksum overflow and odd lengths; every truncation offset; MTU;
spoof admission; malformed headers; variable IP/TCP options; VLAN bounds;
immutable settings; and seeded parser fuzz cases. Linux-specific tests use
local Unix socket pairs to test deadline updates/reset and concurrent close,
plus an independent BPF interpreter to check generated admission filters.
They do not send IP traffic on host interfaces.

```sh
go test ./internal/packet
go vet ./internal/packet
go test -fuzz FuzzDecodeIPv4 -fuzztime 10s ./internal/packet
```

Rawsocket recovery evidence uses reference file addresses `0x915920`/`0x916160`
and `0x91d2a0`/`0x91d400` for read/write, `0x9164e0`/`0x91d760` for wrappers,
and `0x90b180`/`0x90ae80` for Ethernet/IP/TCP serialization and flag parsing.
Constructors `0x916b40` and `0x91b3e0` initialize sequence and ACK to one;
`0x916b40` references the client default `PA,A` literals, while `0x91d400`
uses the server's fallback `PA` mask.
The corresponding analysis-image addresses include a relocation offset.

Live Linux network-namespace tests and authenticated reference-peer differential
tests are separate requirements before claiming deployment or interoperability.
