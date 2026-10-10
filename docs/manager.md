# Offline Netrix manager — ir_spoof

This manager is independently written in Python 3 using the standard library. It preserves the original manager's create, status, install/update and systemd workflow while using the rebuilt Linux core. The upstream manager at [Karrari-Dev/Netrix-](https://github.com/Karrari-Dev/Netrix-) is the behavioral reference; its commercial script is not copied or relicensed here. Independent rewrite attribution: [t.me/ir_spoof](https://t.me/ir_spoof).

The core language and currently verified protocol compatibility are documented in the main README. A transport appearing in the manager selector does not mean it is implemented: the core must accept its configuration with `-check` before a config or service is installed.

Managed services use the independent core's default fresh encrypted mode. The manager does not select `-compat-v3`; legacy reference interoperability requires an explicitly administered core invocation with that flag.

## Install from a local build or bundle

Requirements: Linux with systemd, Python 3.10 or newer, and a core matching the host architecture. The source installer accepts a locally supplied executable and a trusted expected SHA-256. Obtain the checksum from the verified release manifest or your own completed build.

```sh
sudo sh scripts/install.sh --binary build/netrix --sha256 EXPECTED_64_HEX_SHA256
# Alternatively, select an exact filename from a local checksum manifest:
sudo sh scripts/install.sh --binary bin/netrix --manifest SHA256SUMS --manifest-entry bin/netrix
sudo netrix-manager
```

The command installs `/usr/local/bin/netrix`, `/usr/local/bin/netrix-manager.py`, and the `netrix-manager` launcher. It neither downloads software nor edits shell profiles. Core identity must contain `ir_spoof` in its version string, preventing an accidental original licensed-core installation through this replacement installer.

Existing manager-owned installations can be updated with the same command. The candidate checksum, ELF architecture, version identity and every saved config are checked before active owned tunnels are stopped. Installation switches the core atomically, restores the previous core if restart fails, and restarts only tunnels that were running before the update.

An unrecognized existing `/usr/local/bin/netrix` is preserved. An intentional migration requires its exact current checksum:

```sh
sudo sh scripts/install.sh --binary build/netrix --sha256 NEW_CORE_SHA256 \
  --replace-existing --previous-sha256 EXISTING_CORE_SHA256
```

Original configs or unowned services are not migrated automatically. Keep the original available separately if original peers are still in use; demonstrated wire compatibility belongs in the main compatibility report.

## Create a reverse tunnel

The standard workflow is a server listener and an outward-connecting client. Generate a random local peer secret and transfer it privately to the other server. This secret authenticates your two peers; it is not a vendor license or tracking identifier.

```sh
sudo netrix-manager secret demo
# Transfer /etc/netrix/secrets/demo.psk privately to the client first.
# Server:
sudo netrix-manager create demo --mode server --transport tcpmux \
  --listen 0.0.0.0:4000 --psk-file /etc/netrix/secrets/demo.psk \
  --tcp-ports '127.0.0.1:18080=127.0.0.1:8080' --start
# Client, using the same secret and the real server endpoint:
sudo netrix-manager create demo --mode client --transport tcpmux \
  --peer SERVER_IP:4000 --psk-file /etc/netrix/secrets/demo.psk --start
```

For advanced configs, save JSON and use `sudo netrix-manager create ID --config config.json --start`. JSON is also YAML syntax for the Go core. This avoids a PyYAML bootstrap and supports the exact evolving schema that `netrix -check` understands. The manager does not silently drop fields from imported configuration. Native YAML can still be passed directly to the core, but manager imports are deliberately JSON.

The convenience selector and wizard include `tcpmux`, `tlsmux`, `realitymux`, `kcpmux`, `wsmux`, `wssmux`, `rawsocket`, and `l3`; unsupported combinations are rejected by the core. Profiles are balanced, aggressive, latency, and cpu-efficient. An advanced imported config can specify pools, multiple paths, SMUX, KCP/FEC, compression, encryption, optional stealth, TUN/L3, certificates and PROXY protocol according to the core's compatibility report. New guided and CLI configurations with a peer secret enable encryption by default. Explicit CLI `--no-encryption` selects plaintext compatibility mode; both peers must agree. Imported configurations retain the operator's existing encryption setting.

Direct mode is `--direct`: the server role dials `--peer` and owns forwarding listeners, while the client role listens at `--listen` and serves the backends. Put the exposed forwarding mappings on the server in either mode. TLS listening sides use existing certificate files with `--cert` and `--key`. Dialers can supply a local CA/certificate with `--ca`, otherwise the core uses system roots. `--sni` supplies the certificate's server name; the peer address is the default. Browser TLS (`realitymux`) accepts `--fingerprint chrome|firefox|safari|edge|randomized`. The wizard prompts for the appropriate files and values for the listening or dialing role. The manager never performs ACME account registration or online certificate issuance.

L3 convenience fields are `--l3-carrier raw|udp|icmp|pcap|tcp`, `--local-ip`, `--peer-ip`, `--interface`, `--l3-port`, and TUN options `--tun-name`, `--tun-local`, `--tun-remote`, `--tun-mtu`. Set local and remote TUN CIDRs explicitly and swap them for the other peer. Existing core protocol validation decides whether a particular combination is usable.

Raw KCP (`--transport rawsocket`) uses `--interface`, `--local-ip`, `--peer-ip` and the ordinary listen/peer endpoint port. `--raw-mtu` defaults to 1,450 total IPv4 bytes. Optional `--router-mac` sets the explicit next hop for rawsocket or L3 pcap; when absent, the runtime consults local route/neighbor tables and performs bounded ARP only for the selected on-link next hop. It does not query any website or resolve public-IP metadata. Raw/TUN operation needs the relevant Linux privileges. Advanced pcap filters use an installed system libpcap, with an offline trusted tcpdump compiler fallback; default packet I/O itself does not need libpcap.

## Service commands

```sh
sudo netrix-manager check config.json
sudo netrix-manager status
sudo netrix-manager start demo
sudo netrix-manager health demo
sudo netrix-manager stop demo
sudo netrix-manager restart demo
sudo netrix-manager delete demo --yes
systemctl status netrix-demo.service
journalctl -u netrix-demo.service -f
```

Configurations are mode 0600 in `/etc/netrix`, ownership state is in `/var/lib/netrix-manager`, and units are `netrix-ID.service`. IDs use only lowercase letters, digits, underscores and hyphens. User configuration values never become shell command text in a service. Core dumps are disabled, and the manager refuses to alter a unit that was modified externally. Stop a tunnel before replacing its config with `create ID --replace --config FILE`.

Services are enabled only when started through the manager. Stop leaves the unit enabled for later boot; deletion disables it. Services run with the privileges required by TUN/raw transports. Firewall, routing and TUN cleanup belong to the core's scoped resource ownership; the manager does not delete arbitrary host rules or apply blanket optimizations.

No automatic public-IP lookup, vendor verification/cache, telemetry, global sysctl changes, shell-profile edits, website contacts, or third-party certificate bootstrap is included. Health requests target literal loopback, ignore environment proxy settings, and reject redirects. The endpoint is `/health/detailed`, using a nonzero top-level `health_port` first and otherwise `tun.health_port`; a missing/disabled port is reported as unavailable. User-selected tunnel peers and explicit DNS names still determine the core's normal networking behavior.

## Test without modifying the workstation

```sh
python3 scripts/test-manager.py
python3 scripts/netrix-manager.py --root ./manager-simulation status
```

`--root` is a simulation prefix: it records requested service operations in a local JSON ledger and never invokes host systemd. ELF binaries are still validated normally; on Linux a simulation install can run the independent core's `-version` and `-check` against candidate files without starting tunnels. The regression tests instead use an in-process fake checker and exercise failed candidate validation, failed restart rollback, unowned replacement, checksum selection, service injection, changed-unit protection and symlink protection. Host usernames, paths, credentials and private keys are never embedded in published logs or test artifacts.
