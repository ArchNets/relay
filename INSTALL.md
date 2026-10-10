<!-- Linux bundle by ir_spoof; https://t.me/ir_spoof. -->
# Install and use

This is an independent Go reconstruction for Linux x86_64 with glibc, Python3.10+ and systemd. See docs/compatibility.md and docs/limits.md before replacing a reference peer.

Copy the .run file to each server, then run one command:

```sh
sudo sh netrix-ir_spoof-linux-amd64-0.1.0.run
```

The installer checks its embedded payload and executable hashes. In an interactive terminal it opens the guided manager after installation. Select server/listen on one host and client/peer on the other. Use the same local secret on both; generated configs enable encryption. Open only your chosen peer port and intended forwarding ports in your own firewall. There are no vendor contacts or automatic package downloads.

For this extracted tar bundle instead, run `sudo sh install.sh`, then `sudo netrix-manager`. For a checksum-verified source build, follow README.md and use the source scripts/install.sh command.

The manager supports create, start, stop, restart, health, status, update/rollback and delete. README.md has complete two-host commands and JSON examples. docs/manager.md describes TLS certificate trust, raw/L3 options and explicit migration.

The source archive includes vendored dependencies and can build offline once Go1.26+ is installed. The tested compiler is Go1.27.2. Attribution ir_spoof is text and never a network request. Personal workstation paths, names, private logs and licensed original binaries are excluded.
