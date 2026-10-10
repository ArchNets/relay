<!-- Independent Linux reconstruction by t.me/ir_spoof. -->
# Netrix · ir_spoof

An independently written Linux tunnel core and offline service manager. Attribution: **[t.me/ir_spoof](https://t.me/ir_spoof)**.

The reference is [Karrari-Dev/Netrix-](https://github.com/Karrari-Dev/Netrix-), release v3.0.1. Its Linux binary is UPX-packed, obfuscated Go. This reconstruction therefore uses Go, rather than translating Go's networking and runtime into C. The original source and exact compiler/dependency versions were not available.

**Independent release 0.1.0. This is not a byte-identical executable or a claim of complete original behavior.** Removing vendor licensing and changing encryption necessarily changes the executable. The feature report distinguishes static format recovery, independent-peer tests and reference interoperability, and lists the verified cases and remaining limits.

## Quick Server Installation

Run on any Linux server (amd64 / arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/ArchNets/relay/main/install.sh | sudo bash
```

Launch the interactive manager:

```sh
sudo netrix-manager
```

## Privacy

The core has no vendor license client, license cache, public-IP lookup, analytics, automatic updater, ACME bootstrap or hostname collection. It connects to the peers and forwarding targets configured by the operator. Hostnames in those settings require ordinary DNS; use literal IP addresses to avoid that lookup. Health endpoints bind only `127.0.0.1` and expose counts, not peer IP addresses or secrets. Attribution is text, never a network request.

An optional local peer secret protects your own peers, separately from commercial IP licensing. Ordinary tunnels authenticate this token; it is visible on the wire unless encryption or TLS protects the connection. Empty `psk` disables that ordinary authentication check. Encrypted L3 packets use AEAD authentication. Plaintext L3 has a session ID and peer filters, but no cryptographic authentication, even with a PSK. Optional PROXY protocol passes a connection's source address to your configured backend only when you enable it. Keep it off if that metadata is unnecessary.

Encrypted independent peers exchange fresh random values to derive a new key for every connection. The reference reuses a configured key with counters restarted on each connection. `-compat-v3` explicitly selects that recovered legacy encrypted wire behavior; both independent peers normally run without this flag. It also retains the reference behavior of skipping compression when ordinary encryption is enabled.

## Build on Linux

Install Go 1.26 or newer; the tested toolchain is Go 1.27.2. Build from the supplied vendor tree without network access and strip local build paths:

```sh
export GOTELEMETRY=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0
mkdir -p build
CGO_ENABLED=0 go build -mod=vendor -trimpath -buildvcs=false -ldflags='-s -w' -o build/netrix ./cmd/netrix
./build/netrix -version
go test -mod=vendor ./...
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/test-manager.py
```

The dependencies and their licenses are vendored. Updating them is a separate network operation. Runtime does not download dependencies. The supplied amd64 executable requires **glibc Linux**, including the standard ELF loader, libc, libpthread and libdl; `CGO_ENABLED=0` does not make the purego dynamic-loader integration static. Alpine/musl alone is not supported by this bundle. Standard Linux `ip` is required for TUN and optional MAC discovery; Python 3.10+ and systemd are required for the manager. `iptables` is required only for enabled L2TP forwarding. A custom pcap filter needs system libpcap or trusted system tcpdump; other packet modes use owned Linux sockets directly.

## Install a local build

```sh
sudo sh scripts/install.sh --binary build/netrix --sha256 "$(sha256sum build/netrix | cut -d' ' -f1)"
sudo netrix-manager
```

The wizard creates a configuration and a service. The installer uses your local executable and checksum. It does not fetch the original licensed core. See [manager commands](docs/manager.md) for updates, rollback, explicit migration and service ownership.

## A reverse TCP/UDP tunnel

Replace `SERVER_A_IP` with the peer you control. On server A, save `server.json`:

```json
{
  "mode": "server", "listen": "0.0.0.0:4000", "transport": "tcpmux",
  "psk": "REPLACE_WITH_THE_SAME_LOCAL_SECRET_ON_BOTH_PEERS",
  "encryption": {"enabled": true, "algorithm": "chacha20-poly1305"},
  "maps": [
    {"type": "tcp", "bind": "127.0.0.1:18080", "target": "127.0.0.1:8080"},
    {"type": "udp", "bind": "127.0.0.1:18081", "target": "127.0.0.1:8081"}
  ]
}
```

On server B, save `client.json`:

```json
{
  "mode": "client", "transport": "tcpmux",
  "psk": "REPLACE_WITH_THE_SAME_LOCAL_SECRET_ON_BOTH_PEERS",
  "encryption": {"enabled": true, "algorithm": "chacha20-poly1305"},
  "paths": [{"transport": "tcpmux", "addr": "SERVER_A_IP:4000", "connection_pool": 1}]
}
```

Protect configuration permissions with `chmod 600 server.json` on A and `chmod 600 client.json` on B. Validate without network activity using `netrix -config server.json -check` on A and the equivalent `client.json` command on B. Create the two services with `sudo netrix-manager create demo --config server.json --start` on A and the equivalent `client.json` command on B. A's forwarding listeners reach B's local backends; B initiates the peer connection. The example forwarding listeners bind to loopback; choose a suitable local bind address if remote users should access them.

Ordinary stream transports retain this forwarding schema. Set the server transport and the client's path transport consistently and provide the selected transport's additional settings. TLS modes verify certificates by default. Supply a server `cert_file`/`key_file`, a client `ca_file` containing your local CA/certificate, and matching `sni` when the certificate names a hostname. `advanced.tls_insecure_skip_verify: true` is an explicit lab option. Rawsocket requires interface/IP settings; L3 requires a carrier and mirrored TUN/IP settings. Use the guided manager or [transport workflow](docs/manager.md) for those modes. There is no automatic certificate website contact.

## Implementation and evidence

- [Core architecture](docs/core.md)
- [Recovered packet and session formats](docs/wire-format.md)
- [Offline installation and two-server setup](docs/install.md)
- [Manager and service workflow](docs/manager.md)
- [Compatibility and test evidence](docs/compatibility.md)
- [Linux test report](docs/test-report.md)
- [Structured test results](docs/test-results.json)
- [Input hashes and provenance](docs/provenance.json)
- [Explicit limits and differences](docs/limits.md)

The installer is a fresh implementation of the upstream manager's workflow. The commercially described original script and binary are not included or represented as newly authored source. Dependencies retain their own licenses and attribution. Independent code credit: **ir_spoof**.
