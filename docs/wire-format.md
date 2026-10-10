<!-- Independent protocol reconstruction by ir_spoof; https://t.me/ir_spoof. -->
# Wire formats

Protocol reconstruction by [ir_spoof](https://t.me/ir_spoof). This describes the independently written Go implementation and the recovered framing it preserves. It is an implementer's reference, not a claim of identical original behavior, performance, tuning policy or executable bytes. Live coverage and limitations are recorded separately in [compatibility.md](compatibility.md) and [limits.md](limits.md). The reconstruction's [license](../LICENSE) covers its own code; dependencies retain their licenses, and this document does not license or redistribute the original executable.

`BE` means big-endian and `LE` means little-endian. Offsets are zero-based, lengths count bytes, and variable fields follow the preceding fixed fields. TCP reads must assemble complete fields across arbitrary read boundaries; a TCP write, WebSocket message or compression block is not an application packet boundary.

## Ordinary connections and control lines

The stack, from the network inward, is:

```text
TCP / TLS / WS / WSS / KCP / rawsocket
→ optional encrypted or padded records
→ one role/token line
→ optional compression
→ SMUX, optionally containing compressed inner SMUX sessions
→ stream control line and TCP / UDP / TUN data
```

WebSocket carriers upgrade `/ws`; writes use binary messages and reads concatenate their payloads into a byte stream. The named browser-shaped TLS mode is a TLS carrier, not a claim of Xray REALITY compatibility. Ordinary KCP and rawsocket are distinct carriers; the latter's fixed conversation rule is described below.

The physical dialer sends one canonical LF-terminated line:

```text
AUTH <local-token> ROLE=PORTS MUX=<count>\n
AUTH <local-token> ROLE=TUN MUX=<count>\n
```

With an empty ordinary token, the writer instead sends `ROLE PORTS MUX=<count>\n` or `ROLE TUN MUX=<count>\n`. The receiver bounds this line to 4096 bytes. Its no-token legacy fallback can recognize immediate SMUX bytes without consuming them and defaults to `PORTS`, count 1. Tokens are local peer secrets; they are visible when the carrier and records provide no encryption. Normalization trims surrounding whitespace and removes ASCII control characters/DEL; tokens with whitespace remaining after trimming are rejected. Empty tokens disable this ordinary token check. A role is `PORTS` or `TUN`; the multiplex count is 1–64. TUN-enabled ordinary paths create separate physical connection pools for these roles.

The physical dialer creates a SMUX client and the listener creates a SMUX server, including in direct mode. With count 1, application streams use that session. With count greater than 1, the dialer opens that many outer streams; each carries an independent inner SMUX session using the same client/server orientation and optional compression. The outer session itself does not carry application control lines. The public server owns port listeners in both modes; direct mode reverses only carrier connection initiation. Public server mode initiates TUN streams in either mode; accepted and opened TUN streams are both bidirectional.

The eight-byte SMUX header is:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | Version, 1 or 2 |
| 1 | 1 | Command: SYN=0, FIN=1, PSH=2, NOP=3, UPD=4 |
| 2 | 2 | LE payload length |
| 4 | 4 | LE stream ID |
| 8 | length | Payload |

Version 2's UPD payload is two LE32 words: bytes consumed and advertised window. The vendored SMUX implementation supports FIN half-close and retains unread data until the application drains or closes its stream.

Each application stream starts with a bounded, LF-terminated control line:

| Line | Following data |
| --- | --- |
| `CONNECT <host:port>\n` | Bidirectional TCP bytes |
| `CONNECT <host:port> X-Real-IP:<source-host:port>\n` | TCP bytes; configured backend PROXY header may precede them |
| `UDP <host:port>\n` | UDP records below |
| `TUN <index>/<total>\n` | TUN records below; index 1–total, total 1–64 |
| `CTRL\n` | `PING <text>\n` / `PONG <text>\n` control exchange |

Control lines are bounded to 512 bytes. A buffered reader must carry any bytes read beyond the LF into the selected handler. CTRL replies echo the trimmed suffix of `PING ` as `PONG <suffix>\n`; they do not parse or replace the timestamp. Other CTRL input is ignored, and an idle CTRL stream expires after ten minutes. The rewrite answers incoming reference CTRL traffic and uses SMUX keepalive for its own sessions; it does not recreate a separate client CTRL scheduler.

## Ordinary encrypted and padded records

Ordinary AEAD is ChaCha20-Poly1305 or AES-256-GCM. Its base key comes from the normalized `encryption.key`, falling back to the ordinary token: a 32-byte hex value, optionally prefixed with `0x`, is decoded directly; other nonempty text is SHA-256 hashed.

The encrypted record layout is identical in legacy and independent modes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | BE record length L, excluding these two bytes |
| 2 | 12 | Explicit nonce: four zero bytes, then BE64 counter |
| 14 | L−12 | AEAD ciphertext followed by its 16-byte tag |

The two raw length bytes are AEAD associated data. Plaintext is `one-byte padding count | random padding | nonempty data`. The writer splits data into chunks of at most `0xffe0` bytes and bounds padding to 255 bytes. In `-compat-v3`, the physical dialer starts counter 0 and the listener starts 1, including when direct mode reverses their public roles. Independent fresh mode uses public client counter 0 and public server counter 1. Each advances by 2. The receiver rejects replay, wrong prefix/parity and forward jumps over `0x400`; counters never wrap.

Explicit `-compat-v3` uses the static base key and recovered counters across connections. Reusing that key/counter pair carries the reference's nonce-reuse risk. Independent mode first exchanges, outside these records:

```text
physical dialer → listener: "NRX4" | 32 random bytes C
listener → physical dialer: "NRX4" | 32 random bytes S
```

Its session key is one HKDF-SHA256 output block:

```text
PRK = HMAC-SHA256(key=C || S, message=base_key)
session_key = HMAC-SHA256(key=PRK,
                         message="netrix ir_spoof session v4" || byte(1))
```

The random exchange does not itself authenticate its header. Subsequent AEAD records prove possession of the derived secret. This fresh key exchange deliberately differs from legacy peers; both independent endpoints must use it.

Without encryption, enabling padding or jitter selects a different padded format:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | BE **data** length N; excludes padding fields |
| 2 | 1 | Padding count P |
| 3 | P | Random padding |
| 3+P | N | Data |

Data chunks are at most `0x3fe1` bytes. This format has no MAC. Timing jitter changes local send timing, not the record fields.

## Compression and UDP/TUN payloads

When active, compression wraps outer SMUX bytes and, for nested sessions, each inner SMUX byte stream separately. It starts **after** the role/token line. Encrypted v3 compatibility bypasses compression, matching the recovered effective reference path; the independent mode can combine encryption and compression.

| Offset | Size | Compression record field |
| --- | --- | --- |
| 0 | 4 | BE encoded-body length N |
| 4 | 1 | Flag: 0=plain, 1=compressed |
| 5 | N | Plain block or configured codec output |

The codec is configured at both endpoints, not identified inside the record. Zstd uses complete encoded frames, LZ4 uses frames, and the advertised `snappy` codec uses Klauspost S2 blocks. The writer compresses only eligible blocks and uses compressed output only when shorter. Encoded and decoded sizes are bounded by the configured maximum, capped at 1 MiB.

UDP stream records preserve datagram boundaries and return identifiers through the same stream:

| Offset | Size | UDP record field |
| --- | --- | --- |
| 0 | 2 | BE address/flow-identifier length A, 1–256 |
| 2 | 2 | BE datagram payload length N, 0–65535 |
| 4 | A | Address/flow-identifier bytes |
| 4+A | N | Datagram payload |

The UDP control line supplies the remote backend. Record identifiers distinguish original local senders; returned records carry their identifier. CR, LF and NUL are rejected in identifiers.

A TUN record is `BE32 packet length N | N complete IP packet bytes`, with N=1–65535. `IFF_NO_PI` means there is no Linux packet-information prefix. Stream slot indices are one-based on the wire; queue selection, flow hashing and device-reader scheduling are local policies, not packet fields.

## Ordinary rawsocket carrier

Rawsocket carries KCP in Ethernet/IPv4/TCP-shaped datagrams. It does not establish a kernel TCP handshake or implement TCP reliability; KCP supplies reliability. The Ethernet header is destination next-hop MAC, source interface MAC and EtherType `0x0800`. IPv4 is a 20-byte header with protocol 6, TTL 64, zero fragmentation field and a valid header checksum. The shaped TCP header is 20 bytes, no options, window 65535 and a valid IPv4 pseudo-header checksum.

The TCP payload begins with this extra envelope:

| Offset within TCP payload | Size | Field |
| --- | --- | --- |
| 0 | 4 | Reserved; writer emits zero |
| 4 | 2 | **LE** wrapped KCP datagram length N |
| 6 | 2 | Reserved; writer emits zero |
| 8 | N | Wrapped KCP datagram, including configured FEC if enabled |

Sequence/acknowledgement state starts at 1/1; it is shaping state rather than a TCP handshake. Each send advances the shaped sequence by N+8. The dialer chooses an ephemeral source port; listener peers are demultiplexed by admitted source port. Default listener flags are PSH+ACK and the dialer uses the list PSH+ACK/ACK, indexed by shaped sequence modulo list length; explicit flag cycles change this local shaping. Both raw KCP directions use conversation ID **0**. Ordinary UDP KCP is not subject to that raw listener convention.

Configured FEC, when active, precedes KCP: its header is LE32 shard sequence and LE16 shard type (`0xf1` data, `0xf2` parity). A data shard adds LE16 protected-body length, counting that length field, followed by KCP bytes; parity is Reed–Solomon output over protected bodies. Without FEC, KCP begins directly. Its standard 24-byte segment header is LE32 conversation, command byte (PUSH=81, ACK=82, WASK=83, WINS=84), fragment byte, LE16 window, LE32 timestamp, LE32 sequence, LE32 next expected sequence and LE32 payload length, then segment payload. Multiple segments can share one datagram. The vendored KCP/FEC codec controls recovery and congestion policy.

## Standalone L3 / NL3X

L3 transports complete TUN IP packets without SMUX or KCP. Raw-IP uses outer IPv4 protocol 58; UDP and pcap use UDP datagrams; ICMP uses an eight-byte ICMP header; real TCP uses `BE32 complete-record length | NL3X record`. Datagram carriers contain one complete record. Real TCP's four-byte prefix is separate from the internal body-length field.

| Offset | Size | NL3X field |
| --- | --- | --- |
| 0 | 4 | ASCII `NL3X` |
| 4 | 4 | BE session ID |
| 8 | 4 | BE body length B, **including the sequence** |
| 12 | 2 | BE flags: encrypted=1, control=2, fragment=4 |
| 14 | 2 | BE nonzero sending-instance tag |
| 16 | 8 | BE nonzero sequence, incremented for every record |
| 24 | B−8 | Plain payload, or explicit nonce plus AEAD ciphertext/tag |

Normal total length is `16+B`. The complete first 24 bytes are AEAD associated data. Encrypted payload is `12-byte nonce | ciphertext | 16-byte tag`, using AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305. This sender uses all 96 nonce bits from cryptographic randomness per packet, intentionally improving on the recovered random-prefix/counter generation while retaining the explicit-nonce layout. A sending instance stops at 2^32 encrypted packets or entropy failure.

Heartbeat records have control flag 2 and empty logical payload; encryption adds flag 1 and still authenticates that empty payload. Control and fragment flags cannot coexist. A recovered unencrypted zero-body probe can have a 16–24-byte prefix, tag 1 and zero sequence; it never renews trusted peer readiness. Plain L3 has no MAC or authentication handshake: its session ID and replay checks do not authenticate a sender.

For fragmented IP packets, each logical payload starts with:

| Offset within logical payload | Size | Field |
| --- | --- | --- |
| 0 | 4 | BE nonzero message ID |
| 4 | 1 | Fragment count minus one, allowing 2–256 fragments |
| 5 | 1 | Zero-based fragment index |
| 6 | 2 | BE piece-data length N |
| 8 | N | Piece data |

Each fragment has its own NL3X sequence and, when encrypted, its own nonce/tag. Fragment size counts piece data only. The receiver admits authentication/replay before reassembly; local bounds are 64 sending-instance histories, 8192 sequence positions per replay window, 64 incomplete messages, five-second reassembly lifetime and 65535 bytes per assembled IP packet. Inner fragmentation is distinct from optional outer IPv4 fragmentation.

## L3 session ID, key scope and carrier fields

Canonicalize endpoint IP strings and sort the pair lexicographically. If paired spoof addresses exist, those replace the real endpoint pair in the scope. Parse both TUN endpoints into IP strings **without CIDR prefixes**, then lexicographically sort them. Normalize `pcap` to carrier `udp`. Define the wire label as `raw`, `icmp=<type>/<code>`, or `<tcp-or-udp>=<smaller-port>|<larger-port>`.

For encrypted mode, decode the trimmed local L3 secret as raw UTF-8 bytes, or standard Base64 following `b64:` / `base64:`. Normalize the algorithm to `aes-128-gcm`, `aes-256-gcm` or `chacha20-poly1305`. The token is lowercase hex of the first eight bytes of `SHA-256(secret)`. In plaintext mode, algorithm and token are both `none`. Booleans below are lowercase `true`/`false`:

```text
SID_context = nl3|transport=l3|carrier=<carrier>|proto=58|ep=<a>|<b>|wire=<wire>|tun=<ta>|<tb>|enc=<boolean>|algo=<algorithm>|psk=<token>
SID = first four SHA-256(SID_context) bytes interpreted BE32
```

Replace SID zero with `0x13579bdf`. Key derivation uses:

```text
KDF_context = netrix-l3-kdf-v4|sid=<eight-lowercase-hex-digits>|transport=l3|carrier=<carrier>|proto=58|ep=<a>|<b>|wire=<wire>|tun=<ta>|<tb>|enc=true|algo=<algorithm>
salt = SHA-256(KDF_context)
key = PBKDF2-HMAC-SHA256(secret, salt, iterations, key_length)
```

Iterations default to 100000 and are locally capped at 10000000. AES-128 uses 16 key bytes; AES-256 and ChaCha use 32. Prefix lengths configure TUN routing but do not enter SID/KDF. Opposite endpoints mirror real/spoof addresses, ports and TUN IPs. This is static-secret key derivation; L3 does not use NRX4.

For L3 ICMP, identifier is `uint16(SID ^ (SID >> 16))`, with zero replaced by `0x4e45`; both peers admit that identifier. Configured ICMP type/code must agree because they enter the scope. Paired L3 spoofing changes the transmitted **source** only: destination stays the real peer IP, received destination stays the real local IP, and `spoof_dst_ip` is the expected peer's spoofed source. It does not reroute traffic to the spoof address. Real TCP cannot use IP spoofing. Packet checksums, peer admission and local Ethernet next-hop resolution remain carrier responsibilities.
