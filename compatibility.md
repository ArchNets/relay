<!-- Independent compatibility evidence by t.me/ir_spoof. -->
# Compatibility report — Linux release 0.1.0

The final measured candidate passed **58 of 58 independent-core acceptance cases**: 51 primary cases and seven additional fresh-key carrier cases. Native source tests, all 18 Linux manager regressions, offline installation and real systemd service checks also passed. See the [test report](test-report.md) and [structured results](test-results.json) for case identities, exact executable/source hashes, supporting checks and earlier failures.

These results establish the listed behavior in an isolated Linux lab. They do not establish a byte-identical executable or complete original parity. Static recovery, controlled reference comparisons and independent-peer tests remain distinct evidence categories; an independent-peer pass alone is not proof of original interoperability.

| Feature | Final measured evidence |
| --- | --- |
| Ordinary `tcpmux`, `tlsmux`, `realitymux`, `kcpmux`, `wsmux`, `wssmux`, `rawsocket` | All seven passed encrypted, multiplexed TCP/UDP/concurrent echo against both reference roles; all seven also passed between independent peers using default fresh-key NRX4. |
| Authentication, roles and nested SMUX | Exercised by ordinary carrier comparisons; actual-constructor legacy encryption parity passed all eight native mode/direct/physical-role regressions. |
| Ordinary TCP TUN | Bidirectional 56/1200-byte pings, MTU and cleanup passed against both reference roles with `tun.streams: 1`. |
| Concurrent port forwarding and TUN | Independent reverse/direct peers passed with two TUN queues; reference comparisons passed with one queue, both reference roles and both connection modes. Public server owns forwarding listeners in either mode. |
| L3 raw, UDP, ICMP, TCP and pcap | All five passed encrypted, fragmented TUN traffic between independent peers and against both reference roles, including bidirectional pings, MTU and cleanup. |
| L3 paired source spoofing | Raw source-spoof cases passed against both reference roles; independent paired AF_PACKET/source-spoof TUN also passed. This is local-topology evidence, not proof of Internet spoofed-source routing. |
| L3 plaintext and ChaCha20-Poly1305 | Separate independent UDP TUN cases passed. Plaintext L3 has no cryptographic authentication. |
| PROXY protocol and request EOF | Independent PROXY v1/v2 backend cases and response-after-request-EOF passed. Source metadata is sent only when explicitly enabled. |
| Reconnect and negative cases | Raw default-flags/pool-three case passed old-pool expiry after client stop and echo after client restart; actual systemd restart/echo passed. Wrong encryption key and corrupted installer bundle were rejected. |
| Owned L2TP NAT | Ordinary and L3 local/remote forwarding cases passed UDP 500/1701/4500 and owned-rule cleanup; remote routed cases also checked oversized DF rejection. |
| Native source and manager | Offline Go 1.27.2 build and vendored tests passed, with one explicit router-MAC test skip; Linux manager passed 18/18 with no skips. |
| Installer and actual services | Offline production installation, create/enable/start/health, TCP/UDP/concurrent echo, restart, clean stop/delete and unrelated-service preservation passed. |

The native Go suite's explicit skip is `TestLinuxIsolatedLabRouterMACResolution`. The runtime requires glibc Linux; `CGO_ENABLED=0` does not make the purego loader integration fully static. Exact CTRL/PING/PONG responder regressions passed; independent peers use SMUX keepalive rather than reproducing an undocumented original control scheduler.

Controlled reference comparisons use a private, separately hashed analysis derivative with the license getter suppressed, because the unmodified server's vendor licensing prevents an offline listener. Neither that derivative nor private fixture secrets or raw lab captures are distributed. The bounded no-NIC capture audit found no captured destinations outside the allowed lab ranges; it does not prove unrestricted runtime behavior.

Two separately reported reference-only TUN observations are excluded from the 58 acceptance cases. The one-queue pair passed. The two-queue pair admitted its interface addresses, peer routes and initial data probe, then failed a later normal ping. That observation does not by itself establish an upstream defect or universal multiqueue incompatibility. Use one TUN queue for the measured ordinary reference-peer compatibility scope.

Earlier codec/settings coverage of 21 cases used a different executable hash and is historical evidence, not 21 additional final-candidate passes. Compression codecs and security improvements have native coverage, but the final reference matrix does not establish every algorithm, padding choice, carrier combination or original performance policy.

The reference's `realitymux` is observed browser-shaped TLS; Xray REALITY authentication was not established. Unsupported nondefault scheduling/allocator tuning and original diagnostic commands remain explicit [limits](limits.md). Recovered fields and intentional wire differences are documented in [wire format](wire-format.md). Independent reconstruction and testing credit: [ir_spoof](https://t.me/ir_spoof).
