<!-- Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof. -->
# L3 packet core

This package carries complete Linux TUN IP packets in the recovered NL3X format.
It does not use SMUX or KCP. `Run(ctx, config, logger)` owns its TUN interface,
carrier sockets, local health endpoint, forwarding listeners and cleanup.
`Validate(config)` performs no network requests or interface changes.

NL3X records contain a 16-byte fixed header, an eight-byte big-endian sequence,
and payload. The header includes session ID, body length including the sequence,
flags and a nonzero sending-instance tag. Flags are 1 for encryption, 2 for
heartbeat and 4 for inner fragments. Encrypted payload has an explicit 12-byte
nonce followed by AES-GCM or ChaCha20-Poly1305 ciphertext/tag. The full 24-byte
record prefix is authenticated. Real TCP adds a four-byte big-endian length
before each complete record; UDP/raw/ICMP preserve datagram boundaries.

Session ID and PBKDF2 salt cover the sorted endpoint pair, transport/carrier,
ports or ICMP type/code, parsed TUN IP addresses without CIDR prefix lengths,
encryption and algorithm. Both peers must mirror `tun.local` and `tun.remote`;
different representations of the same parsed IP do not change the scope.
AES128 uses a 16-byte key; AES256 and ChaCha20 use 32 bytes. The local peer
secret supplies the encryption key, with no vendor registration. Encrypted
records use AEAD authentication. Plaintext records have no MAC and do not
include the PSK in their session-ID scope.

Inner fragments have an eight-byte prefix: BE32 message ID, count-minus-one,
zero-based index, BE16 piece length, then piece data. Each fragment is separately
sequenced and, when encryption is enabled, authenticated. Encrypted records are
authenticated before replay state or reassembly changes. Plaintext records have
no MAC. A control-only legacy probe cannot renew peer readiness.

The reconstruction has explicit local resource limits: 8192 records per replay
window, 64 sending-instance tags per runtime session without discarding old
replay history, 64 incomplete fragmented messages, 65535 bytes per assembled
packet and a five-second reassembly lifetime. A randomness failure stops cipher
creation instead of using the reference's weak fallback. Malformed trailing
bytes are rejected. The rebuilt sender selects a full cryptographically random
96-bit explicit nonce per encrypted packet, improving on the reference's
four-random-byte prefix plus restarted counter. Record layout and receiver
authentication remain unchanged; nonce generation intentionally differs. A
sending instance stops after 2^32 encrypted packets and requires peer-secret
rotation. The KDF is still the recovered static-secret construction, with no
new per-connection key exchange.

TUN queues, channel capacity and profile/batch scheduling are independently
implemented. The original `sendmmsg` performance implementation is not copied.
The packet socket backend uses explicit peer admission and scoped AF_PACKET
reception for pcap mode. Provide an interface; an explicit next-hop MAC is
optional, with only local routing/neighbor lookup and bounded on-link ARP used
to resolve it. Capture snap length, polling timeout and socket-owned promiscuous
membership are supported. A custom capture expression requires the installed
trusted compiler helper described in `internal/packet`; a missing helper or
invalid expression stops startup.

`allow_ip_frag: true` enables bounded IPv4 fragmentation/reassembly for raw and
ICMP carriers. UDP/pcap retains the recovered UDP DF flag and rejects this
setting. Inner `fragment_size` works with all carriers independently. L2TP
automation installs/removes only invocation-owned NAT chains through the
`internal/firewall` package. It forwards UDP traffic to an existing IPsec/L2TP
service; it does not implement that service. A remote forwarding destination
requires administrator-enabled IPv4 forwarding and matching firewall policy.
The parent README and live test report state the verified runtime coverage.

Unit tests include Python-hashlib-generated SID/PBKDF2 vectors and an independent
full AES-GCM record vector, all AEAD choices, fragment reordering, replay windows,
truncation, stream length bounds, configuration scope and resource exhaustion.
These tests are not proof of byte-identical
recreation or original-to-rebuilt live interoperability.
