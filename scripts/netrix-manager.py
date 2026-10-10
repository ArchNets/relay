#!/usr/bin/env python3
"""Offline Linux tunnel manager, independently written by ir_spoof.

Behavioral reference: Karrari-Dev/Netrix-; this is not the upstream script.
Attribution: https://t.me/ir_spoof
"""
from __future__ import annotations

import argparse
import contextlib
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

CHANNEL = "t.me/ir_spoof"
TRANSPORTS = ("tcpmux", "tlsmux", "realitymux", "kcpmux", "wsmux", "wssmux", "rawsocket", "l3")
PROFILES = ("balanced", "aggressive", "latency", "cpu-efficient")
ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
SHA_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
MAX_CONFIG_BYTES = 1024 * 1024


class ManagerError(RuntimeError):
    pass


class LocalHealthOnly(urllib.request.HTTPRedirectHandler):
    """A local status request must never follow a redirect to another endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ManagerError("Local health redirects are not permitted.")


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def tunnel_id(value: str) -> str:
    if not ID_RE.fullmatch(value):
        raise ManagerError("Tunnel ID must contain 1–48 lowercase letters, digits, underscores or hyphens; start with a letter or digit.")
    return value


def safe_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ManagerError("Expected an ordinary local file, not a link or directory.")


def atomic_bytes(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".netrix-", dir=path.parent)
    try:
        os.fchmod(fd, mode) if hasattr(os, "fchmod") else None
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_config(path: Path) -> dict:
    safe_file(path)
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ManagerError("Configuration is too large.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ManagerError("Manager imports JSON configuration; JSON is also valid YAML for the core.") from error
    if not isinstance(value, dict):
        raise ManagerError("Configuration must be an object.")
    return value


def expected_digest(binary: Path, sha256: str | None, manifest: Path | None, entry: str | None) -> str:
    if sha256:
        if not SHA_RE.fullmatch(sha256):
            raise ManagerError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
        return sha256.lower()
    if not manifest:
        raise ManagerError("Supply --sha256 HASH, or --manifest FILE with an exact --manifest-entry.")
    safe_file(manifest)
    selected = entry or binary.name
    matches = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        found = re.fullmatch(r"([0-9a-fA-F]{64})\s+[* ]?(.+)", line)
        if found and found.group(2) == selected:
            matches.append(found.group(1).lower())
    if len(matches) != 1:
        raise ManagerError("The checksum manifest must contain one exact entry for the selected local core.")
    return matches[0]


def validate_elf(path: Path, machine: str | None = None) -> None:
    with path.open("rb") as handle:
        header = handle.read(64)
    arch = (machine or platform.machine()).lower()
    expected = {"x86_64": 62, "amd64": 62, "aarch64": 183, "arm64": 183}.get(arch)
    if expected is None:
        raise ManagerError("This installer supports Linux x86_64 and arm64; rebuild for the current architecture.")
    if len(header) < 64 or header[:4] != b"\x7fELF" or header[4:7] != b"\x02\x01\x01":
        raise ManagerError("Core must be a 64-bit little-endian Linux ELF executable.")
    if header[7] not in (0, 3) or int.from_bytes(header[18:20], "little") != expected:
        raise ManagerError("Core executable architecture does not match this Linux host.")
    if int.from_bytes(header[16:18], "little") not in (2, 3):
        raise ManagerError("ELF file is not an executable or position-independent executable.")


class Manager:
    """A test root records service operations instead of touching host systemd."""

    def __init__(self, root: Path | None = None, test_core_command: list[str] | None = None):
        self.root = root.resolve() if root else None
        self.test_core_command = test_core_command
        if test_core_command and not self.root:
            raise ManagerError("A test core command requires --root simulation.")

    def path(self, logical: str) -> Path:
        value = PurePosixPath(logical)
        if not value.is_absolute() or ".." in value.parts:
            raise ManagerError("Invalid managed path.")
        if not self.root and platform.system() != "Linux":
            raise ManagerError("Production manager requires Linux; use --root for a local simulation.")
        candidate = self.root.joinpath(*value.parts[1:]) if self.root else Path(str(value))
        stop = self.root if self.root else Path(candidate.anchor)
        cursor = candidate
        while cursor != stop:
            if cursor.is_symlink():
                raise ManagerError("Managed paths must not pass through symbolic links.")
            cursor = cursor.parent
        return candidate

    @property
    def binary(self) -> Path:
        return self.path("/usr/local/bin/netrix")

    @property
    def state_path(self) -> Path:
        return self.path("/var/lib/netrix-manager/state.json")

    def require_write(self) -> None:
        if self.root:
            self.root.mkdir(parents=True, exist_ok=True)
            return
        if platform.system() != "Linux":
            raise ManagerError("Production installation and service management require Linux.")
        if os.geteuid() != 0:
            raise ManagerError("Run this operation with sudo.")

    @contextlib.contextmanager
    def lock(self):
        self.require_write()
        lock_path = self.path("/var/lib/netrix-manager/lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
        try:
            if platform.system() == "Linux":
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX)
            yield
        finally:
            handle.close()

    def state(self) -> dict:
        if not self.state_path.exists():
            return {"schema": 1, "tunnels": {}}
        safe_file(self.state_path)
        value = json.loads(self.state_path.read_text(encoding="utf-8"))
        if value.get("schema") != 1 or not isinstance(value.get("tunnels"), dict):
            raise ManagerError("Unsupported manager state.")
        for name in value["tunnels"]:
            tunnel_id(name)
        return value

    def save_state(self, value: dict) -> None:
        atomic_bytes(self.state_path, json_bytes(value), 0o600)

    def command(self, argv: list[str], timeout: int = 30, acceptable=(0,)) -> subprocess.CompletedProcess:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False)
        if result.returncode not in acceptable:
            # Do not copy arbitrary config/core stderr or host paths into public logs.
            raise ManagerError(f"Command failed with exit code {result.returncode}; inspect local service logs for details.")
        return result

    def core_command(self, core: Path, args: list[str]) -> subprocess.CompletedProcess:
        argv = self.test_core_command + args if self.test_core_command else [str(core)] + args
        return self.command(argv, timeout=30)

    def verify_core_brand(self, core: Path) -> str:
        result = self.core_command(core, ["-version"])
        output = result.stdout.strip()
        if "ir_spoof" not in output or len(output) > 300 or "\n" in output or "\r" in output:
            raise ManagerError("Expected the independently rebuilt ir_spoof core; the original vendor core is not accepted.")
        return output

    def validate_config(self, path: Path, core: Path | None = None) -> None:
        core = core or self.binary
        safe_file(core)
        self.verify_core_brand(core)
        self.core_command(core, ["-config", str(path), "-check"])

    def config_path(self, name: str) -> Path:
        return self.path(f"/etc/netrix/{tunnel_id(name)}.yaml")

    def generate_secret(self, name: str) -> Path:
        name = tunnel_id(name)
        with self.lock():
            target = self.path(f"/etc/netrix/secrets/{name}.psk")
            if target.exists():
                raise ManagerError("A local peer secret already exists for this ID; transfer/reuse it instead of overwriting it.")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_bytes(target, (secrets.token_hex(32) + "\n").encode("ascii"), 0o600)
            return target

    def service_path(self, name: str) -> Path:
        return self.path(f"/etc/systemd/system/netrix-{tunnel_id(name)}.service")

    def service(self, action: str, name: str | None = None) -> bool:
        if action not in ("daemon-reload", "is-active", "start", "stop", "restart", "enable", "disable"):
            raise ManagerError("Unsupported service operation.")
        unit = f"netrix-{tunnel_id(name)}.service" if name else None
        if self.root:
            events = self.path("/var/lib/netrix-manager/simulation.json")
            data = json.loads(events.read_text()) if events.exists() else {"operations": [], "active": [], "enabled": []}
            if action == "is-active":
                return unit in data["active"]
            data["operations"].append({"action": action, "unit": unit})
            for category, additions, removals in (("active", ("start", "restart"), ("stop",)), ("enabled", ("enable",), ("disable",))):
                if action in additions and unit not in data[category]:
                    data[category].append(unit)
                if action in removals and unit in data[category]:
                    data[category].remove(unit)
            atomic_bytes(events, json_bytes(data), 0o600)
            return True
        argv = ["systemctl", action] + ([unit] if unit else [])
        result = self.command(argv, timeout=40, acceptable=(0, 3, 4) if action == "is-active" else (0,))
        return result.returncode == 0

    def owned(self, name: str, state: dict) -> dict:
        name = tunnel_id(name)
        if name not in state["tunnels"]:
            raise ManagerError("This tunnel is not owned by this manager.")
        record = state["tunnels"][name]
        unit_path = self.service_path(name)
        if unit_path.exists():
            safe_file(unit_path)
            if digest(unit_path) != record.get("unit_sha256"):
                raise ManagerError("Service was changed outside the manager; refusing to alter an unrecognized unit.")
        return record

    def unit_bytes(self, name: str) -> bytes:
        name = tunnel_id(name)
        # Names and paths are fixed/sanitized. No /bin/sh, external probes or license state.
        return (f"# Independent manager by ir_spoof — {CHANNEL}\n"
                "[Unit]\nDescription=Netrix independent tunnel\nAfter=network-online.target\nWants=network-online.target\n\n"
                f"[Service]\nType=simple\nExecStart=/usr/local/bin/netrix -config /etc/netrix/{name}.yaml\n"
                "Restart=on-failure\nRestartSec=5\nTimeoutStopSec=20\nKillMode=control-group\n"
                "UMask=0077\nLimitNOFILE=1048576\nLimitCORE=0\nNoNewPrivileges=true\n\n"
                "[Install]\nWantedBy=multi-user.target\n").encode("utf-8")

    def create(self, name: str, config: dict, replace: bool = False, start: bool = False) -> None:
        name = tunnel_id(name)
        with self.lock():
            state = self.state()
            target = self.config_path(name)
            if target.exists() and (name not in state["tunnels"] or not replace):
                raise ManagerError("Configuration exists; use --replace only for a manager-owned tunnel.")
            if name in state["tunnels"]:
                self.owned(name, state)
                if self.service("is-active", name):
                    raise ManagerError("Stop the tunnel before replacing its configuration.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".check-", dir=target.parent) as folder:
                candidate = Path(folder) / "config.yaml"
                atomic_bytes(candidate, json_bytes(config), 0o600)
                self.validate_config(candidate)
                atomic_bytes(target, candidate.read_bytes(), 0o600)
            unit = self.service_path(name)
            if unit.exists() and name not in state["tunnels"]:
                target.unlink()
                raise ManagerError("An existing unowned service uses this tunnel ID; choose another ID.")
            content = self.unit_bytes(name)
            atomic_bytes(unit, content, 0o644)
            state["tunnels"][name] = {"config_sha256": digest(target), "unit_sha256": hashlib.sha256(content).hexdigest()}
            self.save_state(state)
            self.service("daemon-reload")
            if start:
                self.service("enable", name)
                self.service("start", name)

    def action(self, action: str, name: str) -> None:
        with self.lock():
            state = self.state()
            self.owned(name, state)
            if action in ("start", "restart"):
                self.validate_config(self.config_path(name))
            if action == "start":
                self.service("enable", name)
            if action == "delete":
                self.service("stop", name)
                self.service("disable", name)
                for path in (self.service_path(name), self.config_path(name)):
                    with contextlib.suppress(FileNotFoundError):
                        safe_file(path)
                        path.unlink()
                del state["tunnels"][name]
                self.save_state(state)
                self.service("daemon-reload")
            else:
                self.service(action, name)

    def status(self, name: str | None = None) -> list[dict]:
        state = self.state()
        names = [tunnel_id(name)] if name else sorted(state["tunnels"])
        records = []
        for item in names:
            self.owned(item, state)
            records.append({"id": item, "active": self.service("is-active", item), "config": f"/etc/netrix/{item}.yaml"})
        return records

    def install(self, source: Path, expected: str, replace_existing: bool = False, previous_sha256: str | None = None) -> str:
        safe_file(source)
        if digest(source) != expected:
            raise ManagerError("Local core SHA-256 does not match the expected checksum.")
        validate_elf(source)
        with self.lock():
            state = self.state()
            target = self.binary
            existed = target.exists()
            if existed:
                safe_file(target)
                old_sha = digest(target)
                if state.get("core_sha256") != old_sha:
                    if not replace_existing or previous_sha256 != old_sha:
                        raise ManagerError("Existing core is not manager-owned; preserve it or pass --replace-existing with its exact --previous-sha256.")
            active = []
            for name in sorted(state["tunnels"]):
                self.owned(name, state)
                if self.service("is-active", name):
                    active.append(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            candidate = self.path("/usr/local/bin/.netrix-candidate")
            backup = self.path("/usr/local/bin/.netrix-rollback")
            if candidate.exists() or backup.exists():
                raise ManagerError("An unfinished installation exists; inspect the local candidate/rollback files before retrying.")
            replaced = False
            stopped = []
            try:
                atomic_bytes(candidate, source.read_bytes(), 0o755)
                if digest(candidate) != expected:
                    raise ManagerError("Core changed while being copied; installation was cancelled.")
                version = self.verify_core_brand(candidate)
                for name in state["tunnels"]:
                    self.validate_config(self.config_path(name), core=candidate)
                for name in active:
                    self.service("stop", name)
                    stopped.append(name)
                if existed:
                    atomic_bytes(backup, target.read_bytes(), stat.S_IMODE(target.stat().st_mode))
                os.replace(candidate, target)
                replaced = True
                for name in active:
                    self.service("start", name)
                state["core_sha256"] = expected
                state["core_version"] = version
                self.install_manager_files()
                self.save_state(state)
                return version
            except Exception:
                if replaced:
                    for name in active:
                        with contextlib.suppress(Exception):
                            self.service("stop", name)
                    if existed and backup.exists():
                        os.replace(backup, target)
                    elif not existed:
                        with contextlib.suppress(FileNotFoundError):
                            target.unlink()
                for name in stopped:
                    with contextlib.suppress(Exception):
                        self.service("start", name)
                raise
            finally:
                for path in (candidate, backup):
                    with contextlib.suppress(FileNotFoundError):
                        path.unlink()

    def install_manager_files(self) -> None:
        own_source = Path(__file__)
        atomic_bytes(self.path("/usr/local/bin/netrix-manager.py"), own_source.read_bytes(), 0o755)
        launcher = b'#!/bin/sh\n# Offline manager by ir_spoof; t.me/ir_spoof\nexec python3 /usr/local/bin/netrix-manager.py "$@"\n'
        atomic_bytes(self.path("/usr/local/bin/netrix-manager"), launcher, 0o755)

    def health(self, name: str) -> dict:
        state = self.state()
        self.owned(name, state)
        config = read_config(self.config_path(name))
        port = config.get("health_port") or (config.get("tun") or {}).get("health_port", 0)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ManagerError("Invalid local health port.")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalHealthOnly())
        with opener.open(f"http://127.0.0.1:{port}/health/detailed", timeout=3) as response:
            content = response.read(MAX_CONFIG_BYTES + 1)
        if len(content) > MAX_CONFIG_BYTES:
            raise ManagerError("Local health response is too large.")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ManagerError("Invalid local health response.")
        return value


def port_strings(value: str) -> list[str]:
    result = [part.strip() for part in value.split(",") if part.strip()]
    if any("\n" in part or "\r" in part or "\x00" in part for part in result):
        raise ManagerError("Invalid port mapping.")
    return result


def build_config(args: argparse.Namespace) -> dict:
    if args.config:
        return read_config(Path(args.config))
    if not args.mode:
        raise ManagerError("Supply --config FILE, or --mode server/client with endpoint settings.")
    psk = ""
    if args.psk_file:
        safe_file(Path(args.psk_file))
        psk = Path(args.psk_file).read_text(encoding="utf-8").strip()
        if not psk:
            raise ManagerError("Peer-authentication file is empty.")
    config = {"mode": args.mode, "profile": args.profile, "psk": psk, "transport": args.transport,
              "tcp_ports": port_strings(args.tcp_ports), "udp_ports": port_strings(args.udp_ports),
              "health_port": args.health_port, "verbose": False,
              "encryption": {"enabled": bool(psk) and not args.no_encryption, "algorithm": "chacha20-poly1305"}}
    if args.transport == "l3":
        if not (args.local_ip and args.peer_ip and args.interface):
            raise ManagerError("L3 requires --local-ip, --peer-ip and --interface.")
        for address in (args.local_ip, args.peer_ip):
            ipaddress.ip_address(address)
        config["tun"] = {"enabled": True, "name": args.tun_name, "local": args.tun_local,
                         "remote": args.tun_remote, "mtu": args.tun_mtu, "streams": 1, "health_port": args.health_port}
        config["l3"] = {"carrier": args.l3_carrier, "interface": args.interface, "listen_ip": args.local_ip,
                        "dst_ip": args.peer_ip, "listen_port": args.l3_port, "dst_port": args.l3_port,
                        "heartbeat_interval": 5, "heartbeat_timeout": 30, "enable_encryption": bool(psk) and not args.no_encryption,
                        "algorithm": "aes-256-gcm", "psk": psk, "kdf_iterations": 100000}
        if args.router_mac:
            config["rawsocket"] = {"router_mac": args.router_mac}
        return config
    if args.mode == "server":
        if args.direct:
            if not args.peer:
                raise ManagerError("A direct server requires --peer HOST:PORT.")
            config.update({"direct": True, "connect": args.peer, "connection_pool": args.pool})
        else:
            config["listen"] = args.listen
    elif args.direct:
        config.update({"direct": True, "listen": args.listen})
    else:
        if not args.peer:
            raise ManagerError("A reverse client requires --peer HOST:PORT.")
        config["paths"] = [{"transport": args.transport, "addr": args.peer, "connection_pool": args.pool,
                            "retry_interval": 3, "dial_timeout": 10}]
    if args.cert or args.key:
        if not (args.cert and args.key):
            raise ManagerError("Supply both --cert and --key.")
        config.update({"cert_file": args.cert, "key_file": args.key})
    if args.ca:
        config["ca_file"] = args.ca
    if args.sni or args.transport == "realitymux":
        config["reality"] = {"sni": args.sni or "", "fingerprint": args.fingerprint}
    if args.transport == "rawsocket":
        if not (args.local_ip and args.peer_ip and args.interface):
            raise ManagerError("Rawsocket requires --local-ip, --peer-ip and --interface.")
        for address in (args.local_ip, args.peer_ip):
            if ipaddress.ip_address(address).version != 4:
                raise ManagerError("Rawsocket requires literal IPv4 addresses.")
        config["rawsocket"] = {"interface": args.interface, "local_ip": args.local_ip,
                               "peer_ip": args.peer_ip, "router_mac": args.router_mac or "", "mtu": args.raw_mtu}
    if args.tun:
        config["tun"] = {"enabled": True, "name": args.tun_name, "local": args.tun_local, "remote": args.tun_remote,
                         "mtu": args.tun_mtu, "routes": [], "streams": 1}
    return config


def prompt(label: str, default: str = "") -> str:
    answer = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
    return answer or default


def wizard(manager: Manager) -> None:
    print(f"Netrix independent Linux manager — {CHANNEL}")
    while True:
        print("\n1) Create tunnel  2) Status  3) Start  4) Stop  5) Restart  6) Delete  7) Install local core  0) Exit")
        choice = prompt("Select", "0")
        if choice == "0":
            return
        try:
            if choice == "1":
                name = tunnel_id(prompt("Tunnel ID", "demo"))
                imported = prompt("Existing JSON configuration file; empty for guided setup")
                if imported:
                    config = read_config(Path(imported))
                else:
                    role = prompt("Role: server/client", "server")
                    transport = prompt("Transport: " + "/".join(TRANSPORTS), "tcpmux")
                    if role not in ("server", "client") or transport not in TRANSPORTS:
                        raise ManagerError("Unknown role or transport.")
                    profile = prompt("Profile: " + "/".join(PROFILES), "balanced")
                    if profile not in PROFILES:
                        raise ManagerError("Unknown profile.")
                    secret = getpass.getpass("Local peer-authentication PSK (hidden; empty generates a new local secret): ")
                    if not secret:
                        secret_file = manager.generate_secret(name)
                        secret = secret_file.read_text(encoding="ascii").strip()
                        print(f"Generated /etc/netrix/secrets/{name}.psk; transfer this file privately to the peer.")
                    config = {"mode": role, "transport": transport, "profile": profile, "psk": secret, "verbose": False,
                              "tcp_ports": [], "udp_ports": [],
                              "encryption": {"enabled": bool(secret), "algorithm": "chacha20-poly1305"}}
                    if role == "server":
                        config["tcp_ports"] = port_strings(prompt("TCP mappings; empty to skip"))
                        config["udp_ports"] = port_strings(prompt("UDP mappings; empty to skip"))
                    config["health_port"] = int(prompt("Health port", "19080"))
                    if transport == "l3":
                        local_default = "10.200.0.1/30" if role == "server" else "10.200.0.2/30"
                        remote_default = "10.200.0.2/30" if role == "server" else "10.200.0.1/30"
                        config["tun"] = {"enabled": True, "name": prompt("TUN name", "netrix0"),
                                         "local": prompt("Local TUN CIDR", local_default), "remote": prompt("Peer TUN CIDR", remote_default),
                                         "mtu": int(prompt("TUN MTU", "1320")), "streams": 1, "health_port": config["health_port"]}
                        carrier = prompt("L3 carrier: raw/udp/icmp/pcap/tcp", "udp")
                        config["l3"] = {"carrier": carrier, "listen_ip": prompt("Local outer IP"), "dst_ip": prompt("Peer outer IP"),
                                        "interface": prompt("Physical interface"), "listen_port": 40001, "dst_port": 40001,
                                        "enable_encryption": bool(secret), "algorithm": "aes-256-gcm", "psk": secret, "kdf_iterations": 100000}
                        if carrier == "pcap":
                            router_mac = prompt("Next-hop MAC; empty for local route/ARP resolution")
                            if router_mac:
                                config["rawsocket"] = {"router_mac": router_mac}
                    else:
                        direct = prompt("Connection: reverse/direct", "reverse") == "direct"
                        config["direct"] = direct
                        if (role == "server") != direct:
                            config["listen"] = prompt("Listen address", "0.0.0.0:4000")
                        else:
                            peer = prompt("Peer address: HOST:PORT")
                            if role == "server":
                                config["connect"] = peer
                            else:
                                config["paths"] = [{"transport": transport, "addr": peer, "connection_pool": 8}]
                        if transport in ("tlsmux", "wssmux", "realitymux"):
                            listening = (role == "server") != direct
                            if listening:
                                config.update({"cert_file": prompt("Existing certificate file"), "key_file": prompt("Existing private-key file")})
                            else:
                                ca_file = prompt("Local trusted CA/certificate file; empty for system roots")
                                if ca_file:
                                    config["ca_file"] = ca_file
                                sni = prompt("TLS server name matching certificate; empty to use peer address")
                                fingerprint = prompt("Browser fingerprint: chrome/firefox/safari/edge/randomized", "chrome") if transport == "realitymux" else "chrome"
                                if sni or transport == "realitymux":
                                    config["reality"] = {"sni": sni, "fingerprint": fingerprint}
                        if transport == "rawsocket":
                            config["rawsocket"] = {"interface": prompt("Physical interface"), "local_ip": prompt("Local outer IPv4"),
                                                   "peer_ip": prompt("Peer outer IPv4"), "router_mac": prompt("Next-hop MAC; empty for local route/ARP resolution"),
                                                   "mtu": int(prompt("Total outer IPv4 MTU", "1450"))}
                manager.create(name, config, start=prompt("Start and enable after validation? y/n", "n").lower() == "y")
                print("Configuration validated and installed.")
            elif choice == "2":
                print(json.dumps(manager.status(), indent=2))
            elif choice in ("3", "4", "5", "6"):
                action = {"3": "start", "4": "stop", "5": "restart", "6": "delete"}[choice]
                name = tunnel_id(prompt("Tunnel ID"))
                if action == "delete" and prompt("Remove this manager-owned config and unit? y/n", "n") != "y":
                    continue
                manager.action(action, name)
                print("Completed.")
            elif choice == "7":
                source = Path(prompt("Local independently rebuilt core file"))
                sha = expected_digest(source, prompt("Expected SHA-256"), None, None)
                print(manager.install(source, sha))
            else:
                print("Unknown menu option.")
        except (ManagerError, OSError, ValueError, subprocess.SubprocessError) as error:
            print(f"Error: {error}", file=sys.stderr)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=f"Offline Linux Netrix manager by ir_spoof — {CHANNEL}")
    result.add_argument("--root", type=Path, help="Simulation directory: no host systemd operations or installation")
    result.add_argument("--test-core-command", help=argparse.SUPPRESS)
    sub = result.add_subparsers(dest="command")
    install = sub.add_parser("install", help="Install/update a locally supplied, checksum-verified core")
    install.add_argument("--binary", required=True, type=Path)
    checksum = install.add_mutually_exclusive_group(required=True)
    checksum.add_argument("--sha256")
    checksum.add_argument("--manifest", type=Path)
    install.add_argument("--manifest-entry")
    install.add_argument("--replace-existing", action="store_true")
    install.add_argument("--previous-sha256")
    create = sub.add_parser("create", help="Validate a config with the local core before creating a service")
    create.add_argument("id", type=tunnel_id)
    create.add_argument("--config")
    create.add_argument("--mode", choices=("server", "client"))
    create.add_argument("--transport", choices=TRANSPORTS, default="tcpmux")
    create.add_argument("--profile", choices=PROFILES, default="balanced")
    create.add_argument("--listen", default="0.0.0.0:4000")
    create.add_argument("--peer")
    create.add_argument("--direct", action="store_true")
    create.add_argument("--pool", type=int, default=8)
    create.add_argument("--psk-file")
    create.add_argument("--no-encryption", action="store_true", help="Explicit plaintext compatibility mode; both peers must match")
    create.add_argument("--tcp-ports", default="")
    create.add_argument("--udp-ports", default="")
    create.add_argument("--health-port", type=int, default=19080)
    create.add_argument("--cert")
    create.add_argument("--key")
    create.add_argument("--ca", help="Existing local trusted CA/certificate file for a TLS dialer")
    create.add_argument("--sni", help="TLS server name matching the operator's certificate")
    create.add_argument("--fingerprint", choices=("chrome", "firefox", "safari", "edge", "randomized"), default="chrome")
    create.add_argument("--tun", action="store_true")
    create.add_argument("--tun-name", default="netrix0")
    create.add_argument("--tun-local", default="10.200.0.1/30")
    create.add_argument("--tun-remote", default="10.200.0.2/30")
    create.add_argument("--tun-mtu", type=int, default=1400)
    create.add_argument("--l3-carrier", choices=("raw", "udp", "icmp", "pcap", "tcp"), default="udp")
    create.add_argument("--interface")
    create.add_argument("--local-ip")
    create.add_argument("--peer-ip")
    create.add_argument("--router-mac", help="Optional explicit next-hop MAC; otherwise resolve locally at runtime")
    create.add_argument("--raw-mtu", type=int, default=1450)
    create.add_argument("--l3-port", type=int, default=40001)
    create.add_argument("--replace", action="store_true")
    create.add_argument("--start", action="store_true")
    for operation in ("start", "stop", "restart", "delete", "health"):
        action = sub.add_parser(operation)
        action.add_argument("id", type=tunnel_id)
        if operation == "delete":
            action.add_argument("--yes", action="store_true", required=True)
    status = sub.add_parser("status")
    status.add_argument("id", nargs="?", type=tunnel_id)
    secret = sub.add_parser("secret", help="Generate a random local peer-authentication file without printing its contents")
    secret.add_argument("id", type=tunnel_id)
    check = sub.add_parser("check")
    check.add_argument("config", type=Path)
    check.add_argument("--binary", type=Path)
    sub.add_parser("menu")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        manager = Manager(args.root, shlex.split(args.test_core_command) if args.test_core_command else None)
        if args.command == "install":
            sha = expected_digest(args.binary, args.sha256, args.manifest, args.manifest_entry)
            print(manager.install(args.binary, sha, args.replace_existing, args.previous_sha256))
            print(f"Offline core and manager installed. Attribution: {CHANNEL}")
        elif args.command == "create":
            manager.create(args.id, build_config(args), args.replace, args.start)
            print(f"Tunnel {args.id} validated and created. Attribution: {CHANNEL}")
        elif args.command in ("start", "stop", "restart", "delete"):
            manager.action(args.command, args.id)
            print(f"Tunnel {args.id}: {args.command} completed.")
        elif args.command == "status":
            print(json.dumps(manager.status(args.id), indent=2))
        elif args.command == "secret":
            manager.generate_secret(args.id)
            print(f"Generated /etc/netrix/secrets/{args.id}.psk; transfer this file privately to the peer.")
        elif args.command == "health":
            print(json.dumps(manager.health(args.id), indent=2))
        elif args.command == "check":
            manager.validate_config(args.config, args.binary)
            print("Configuration check passed.")
        else:
            wizard(manager)
        return 0
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except (ManagerError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
