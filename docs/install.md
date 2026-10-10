<!-- Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof. -->
# Install and connect two Linux servers

The supplied runtime bundle targets Linux x86_64 with glibc, Python 3.10 or
newer and systemd. Its additional transport dependencies are described in the
main README. Copy the installer to each server and run:

```sh
sudo sh netrix-ir_spoof-linux-amd64-0.1.0.run
```

The installer validates the local payload and executable hashes. In an
interactive terminal it opens the manager after installation. It does not
download the original core or contact a verification service.

Choose server mode on server A and client mode on server B. In the normal
reverse tunnel, A listens and B connects to A. Choose the same transport on
both sides. Generate a local peer secret once on A and transfer that same
secret privately to B; new guided configurations enable encryption. The secret
protects your own peers and is independent of vendor licensing.

For a first TCP/UDP forwarding tunnel, choose `tcpmux`. Set A's peer listening
endpoint, set B's peer endpoint to that address, and add forwarding listeners
on A whose targets are reachable from B. A listener bound to `127.0.0.1` is
accessible only on A; choose an appropriate local bind address for remote
clients. The main README contains complete JSON examples and service commands.

TLS listening modes use an existing certificate and key. The dialing peer
needs matching SNI and either a local CA file or a certificate trusted by its
system roots. Rawsocket and L3 also need their interface, address and
TUN/carrier settings; changing only a transport name is insufficient.

Inspect an installed tunnel with:

```sh
sudo netrix-manager status
sudo netrix-manager health demo
systemctl status netrix-demo.service
journalctl -u netrix-demo.service -f
```

For an extracted runtime tar bundle, run `sudo sh install.sh`, then
`sudo netrix-manager`. For a source build, extract the source archive and run
the following commands from its source root with Go 1.26 or newer already
installed. The tested compiler is Go 1.27.2.

```sh
sh scripts/build.sh
GOTELEMETRY=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 go test -mod=vendor ./...
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/test-manager.py
sudo sh scripts/install.sh --binary build/netrix --sha256 "$(sha256sum build/netrix | cut -d' ' -f1)"
sudo netrix-manager
```

Dependencies are included for offline builds. The manager is an independently
written replacement for the upstream local install/create/start/stop/status
workflow. It does not copy or relicense the original script. Vendor downloads,
public-IP discovery, license/cache checks, ACME and global optimizer changes
are absent. The core CLI uses local configuration files; original flag-only
configuration and debug/reset-stream commands are not recreated.

Read [compatibility](compatibility.md) and [limits](limits.md) for the measured
coverage and remaining differences. Attribution to [ir_spoof](https://t.me/ir_spoof)
is text and causes no network request.
