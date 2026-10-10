<!-- Independent testing by ir_spoof; https://t.me/ir_spoof. -->
# Netrix ir_spoof test report

Independent release 0.1.0 for Linux amd64; reference release v3.0.1.
The results separate independent-peer behavior, controlled reference comparisons, reference-only observations and earlier snapshots.
They do not establish byte-identical recreation or complete original parity.

Final measured status: **passed measured cases**. The primary plan contains 51 cases: 51 passed, 0 failed, 0 missing and 0 invalid.
Seven additional final-candidate independent fresh-key carrier cases: 7 passed, 0 failed, 0 missing and 0 invalid.
Release acceptance therefore covers 58 cases: 58 passed, 0 failed, 0 missing and 0 invalid, plus the required native, manager, service, package and capture checks.
Two reference-only observations are reported separately and are excluded from these acceptance counts.

All 58 final acceptance cases and supporting checks come from one admitted final run with fresh output directories.
That run includes the native source build, full Go suite, 18 manager regressions, actual installer and systemd services, and package checks for the same frozen candidate and source.
Failed admission and readiness/handshake observations on a different earlier candidate are retained separately. Earlier and inherited records do not contribute to final acceptance.

Candidate executable SHA-256: `3752c473cfc4ba4e4056dd28879f19be37722167d4ab0c8ef22b971aa509c705`.
Admitted native input snapshot SHA-256: `715027cf32859b74f4b148b8022c81d6b1c9bb10b875ca5b94af38262352352d`.
This source hash identifies the tested input before report-only updates. Final published archive hashes belong in `SHA256SUMS`.

## Native build and supporting checks

| Check | Result |
| --- | --- |
| Native offline build | passed |
| Vendored Go tests | passed |
| Linux manager regressions | passed |
| Offline installer and real systemd | passed |
| Candidate runtime/source package | passed |
| Bounded packet audit | passed |

The verified native build uses Go 1.27.2, the local vendor tree, disabled download endpoints and telemetry, and `-trimpath`/`-buildvcs=false`.
The runtime requires glibc loader libraries; `CGO_ENABLED=0` does not make the purego loader integration fully static.

Explicit native unit-test skips: **1**.
- `TestLinuxIsolatedLabRouterMACResolution`

Exact CTRL responder regressions extracted from the native test log:
- `TestControlRepliesPreserveLookaheadAndTimestamp`: passed.
- `TestControlOversizedLineCloses`: passed.
- `TestControlIdleDeadline`: passed.
- `TestControlDispatchAcceptsSingleFieldHeader`: passed.

Actual-constructor legacy crypto regression `TestLegacyCryptoUsesPhysicalConnectionParity`: passed; 8 of eight mode/direct/physical-role subtests passed.

Python manager suite: 18 of 18 expected regressions reported; 18 passed, 0 failed/error, 0 skipped. Suite status: passed.

## Primary final tunnel matrix

| Case | Evidence category | TUN queues | Result |
| --- | --- | --- | --- |
| `diff-tcpmux-reference-server-encrypted-mux2` | controlled reference | — | passed |
| `diff-tcpmux-reference-client-encrypted-mux2` | controlled reference | — | passed |
| `diff-tlsmux-reference-server-encrypted-mux2` | controlled reference | — | passed |
| `diff-tlsmux-reference-client-encrypted-mux2` | controlled reference | — | passed |
| `diff-realitymux-reference-server-encrypted-mux2` | controlled reference | — | passed |
| `diff-realitymux-reference-client-encrypted-mux2` | controlled reference | — | passed |
| `diff-kcpmux-reference-server-encrypted-mux2` | controlled reference | — | passed |
| `diff-kcpmux-reference-client-encrypted-mux2` | controlled reference | — | passed |
| `diff-wsmux-reference-server-encrypted-mux2` | controlled reference | — | passed |
| `diff-wsmux-reference-client-encrypted-mux2` | controlled reference | — | passed |
| `diff-wssmux-reference-server-encrypted-mux2` | controlled reference | — | passed |
| `diff-wssmux-reference-client-encrypted-mux2` | controlled reference | — | passed |
| `diff-rawsocket-reference-server-encrypted-mux2` | controlled reference | — | passed |
| `diff-rawsocket-reference-client-encrypted-mux2` | controlled reference | — | passed |
| `diff-tcpmux-reference-server-tun-queues1` | controlled reference | 1 | passed |
| `diff-tcpmux-reference-client-tun-queues1` | controlled reference | 1 | passed |
| `diff-l3-raw-reference-server-fragmented-tun` | controlled reference | 1 | passed |
| `diff-l3-raw-reference-client-fragmented-tun` | controlled reference | 1 | passed |
| `new-l3-raw-tun-encrypted-fragmented` | independent peers | 1 | passed |
| `diff-l3-udp-reference-server-fragmented-tun` | controlled reference | 1 | passed |
| `diff-l3-udp-reference-client-fragmented-tun` | controlled reference | 1 | passed |
| `new-l3-udp-tun-encrypted-fragmented` | independent peers | 1 | passed |
| `diff-l3-icmp-reference-server-fragmented-tun` | controlled reference | 1 | passed |
| `diff-l3-icmp-reference-client-fragmented-tun` | controlled reference | 1 | passed |
| `new-l3-icmp-tun-encrypted-fragmented` | independent peers | 1 | passed |
| `diff-l3-tcp-reference-server-fragmented-tun` | controlled reference | 1 | passed |
| `diff-l3-tcp-reference-client-fragmented-tun` | controlled reference | 1 | passed |
| `new-l3-tcp-tun-encrypted-fragmented` | independent peers | 1 | passed |
| `diff-l3-pcap-reference-server-fragmented-tun` | controlled reference | 1 | passed |
| `diff-l3-pcap-reference-client-fragmented-tun` | controlled reference | 1 | passed |
| `new-l3-pcap-tun-encrypted-fragmented` | independent peers | 1 | passed |
| `diff-l3-raw-spoof-reference-server-tun` | controlled reference | 1 | passed |
| `diff-l3-raw-spoof-reference-client-tun` | controlled reference | 1 | passed |
| `new-l3-raw-afpacket-paired-spoof-tun` | independent peers | 1 | passed |
| `new-l3-udp-chacha-tun` | independent peers | 1 | passed |
| `new-l3-udp-plain-tun` | independent peers | 1 | passed |
| `new-rawsocket-default-flags-pool3` | independent peers | — | passed |
| `new-tcpmux-wrong-encryption-key-refusal` | independent peers | — | passed |
| `new-tcpmux-proxy-v1` | independent peers | — | passed |
| `new-tcpmux-proxy-v2` | independent peers | — | passed |
| `new-tcpmux-request-eof-response` | independent peers | — | passed |
| `new-tcpmux-l2tp-local-nat-cleanup` | independent peers | 2 | passed |
| `new-tcpmux-l2tp-remote-nat-cleanup` | independent peers | 2 | passed |
| `new-l3-l2tp-local-nat-cleanup` | independent peers | 1 | passed |
| `new-l3-l2tp-remote-nat-cleanup` | independent peers | 1 | passed |
| `final-tcpmux-ports-and-tun-own-reverse` | independent peers | 2 | passed |
| `final-tcpmux-ports-and-tun-own-direct` | independent peers | 2 | passed |
| `final-tcpmux-ports-and-tun-reference-server-queues1` | controlled reference | 1 | passed |
| `final-tcpmux-ports-and-tun-direct-reference-server-queues1` | controlled reference | 1 | passed |
| `final-tcpmux-ports-and-tun-reference-client-queues1` | controlled reference | 1 | passed |
| `final-tcpmux-ports-and-tun-direct-reference-client-queues1` | controlled reference | 1 | passed |

## Additional final independent carriers

These use independently written peers with the default fresh-key NRX4 handshake, encryption enabled and multiplexing set to two.
| Case | Result |
| --- | --- |
| `final-independent-tcpmux-fresh-key-mux2` | passed |
| `final-independent-tlsmux-fresh-key-mux2` | passed |
| `final-independent-realitymux-fresh-key-mux2` | passed |
| `final-independent-kcpmux-fresh-key-mux2` | passed |
| `final-independent-wsmux-fresh-key-mux2` | passed |
| `final-independent-wssmux-fresh-key-mux2` | passed |
| `final-independent-rawsocket-fresh-key-mux2` | passed |

Controlled reference comparisons use a private analysis derivative with the license getter suppressed.
The original input identity remains documented separately. The derivative, modification bytes, private fixture secrets and raw logs are not distributed.
Local health counts alone are not recorded as successful data exchange; each whole-case outcome comes from its durable result JSON.

## Reference-only TUN observations

Both endpoints in these two observations are private reference derivatives. They do not test the independent core and are excluded from the 58 release-acceptance cases.
Address, link and peer-route readiness and the first data probe each have a bounded admission deadline. Observed failures do not by themselves establish an upstream defect.
| Case | TUN queues | Observed whole-case result |
| --- | --- | --- |
| `final-original-pair-tun-queues2-mux2` | 2 | failed |
| `final-original-pair-tun-queues1-mux2` | 1 | passed |
The structured JSON retains allowlisted readiness booleans and admission durations, without addresses, route output, logs or secrets.

## Installer and service steps

| Observed step | Passed |
| --- | --- |
| bundle integrity and executable identity | true |
| corrupted bundle rejection | true |
| offline production installation | true |
| explicit isolated-VM network-online prerequisite | true |
| manager creates the server service | true |
| manager creates the client service | true |
| real service create, enable, start and health | true |
| systemd TCP echo | true |
| systemd UDP echo | true |
| systemd concurrent stream echo | true |
| real service restart and echo | true |
| client clean stop and deletion | true |
| server clean stop and deletion | true |
| unrelated service and scoped cleanup | true |

## Capture scope and earlier coverage

The bounded audit covers 60 of 60 planned cases, with 122 captures and 108471 captured packets; 0 captured destinations were outside the allowed lab ranges.
Capture totals can include repeated observations on multiple namespace interfaces. Bounded captures and the no-NIC topology do not prove unrestricted runtime behavior.

Earlier candidate `c73bc0218f36e2517222f7ea3de3b91e543e0e11189cc0f2939fcd6b129b4253`: its primary job refused an existing output directory before any current case ran; inherited baseline records were excluded.
Three earlier coexistence failures and two earlier reference-only probe failures remain recorded as failure metadata in [test-results.json](test-results.json). They are not final-candidate outcomes.

Earlier candidate `737b4583d94624cc2333270cf80835e8724467d4124c1e32991d98d04594497c`: a native regression-fixture nil-pointer panic and three failed runtime attempts are retained as separate historical metadata.
The final candidate receives a fresh full native suite and all 58 acceptance attempts; earlier passes are not reused.

Earlier non-L3 evidence: **21 passes**, on the different candidate `a8350ec62aed4824ff8f6b50bb83e0c5460811d818146caa2ba5d081c0464ab8`.
These are historical results, not additional final-candidate passes. Their case details and categories are preserved in [test-results.json](test-results.json).

## Distribution review

The final report-only repack must retain the admitted Go/vendor/manager code, preserve dependency licenses, and pass a fresh archive and privacy audit.
Exclude personal identifiers, workstation paths, credentials, raw lab logs/captures, analysis caches and private reference derivatives.
Exact final bundle hashes are in `SHA256SUMS`; candidate package checks do not certify later archive bytes.
Read [limits](limits.md) and [compatibility](compatibility.md) for remaining differences and verified behavior. Attribution to [ir_spoof](https://t.me/ir_spoof) is local text and triggers no network request.
