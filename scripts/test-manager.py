#!/usr/bin/env python3
"""Manager transaction and command-injection regression checks — ir_spoof.

Tests use a temporary simulation root and never invoke systemctl or a real core.
Attribution: t.me/ir_spoof
"""
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("netrix_manager", Path(__file__).with_name("netrix-manager.py"))
manager_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager_module)


def fake_elf(payload: bytes) -> bytes:
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    return bytes(header) + payload


class FakeManager(manager_module.Manager):
    def __init__(self, root: Path):
        super().__init__(root)
        self.checked = []
        self.fail_check = False
        self.fail_start_once = False
        self.reject_brand = False

    def core_command(self, core, args):
        self.checked.append(list(args))
        if args == ["-version"]:
            version = "vendor-core" if self.reject_brand else "Netrix independent 0.1.0 by ir_spoof"
            return subprocess.CompletedProcess(args, 0, version, "")
        if "-check" in args and self.fail_check:
            raise manager_module.ManagerError("Unsupported configuration")
        return subprocess.CompletedProcess(args, 0, "configuration valid", "")

    def service(self, action, name=None):
        if action == "start" and self.fail_start_once:
            self.fail_start_once = False
            raise manager_module.ManagerError("Injected start failure")
        return super().service(action, name)


class ManagerSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="netrix-manager-test-")
        self.root = Path(self.temp.name)
        self.manager = FakeManager(self.root / "host")
        self.old = self.root / "old-core"
        self.new = self.root / "new-core"
        self.old.write_bytes(fake_elf(b"old independently rebuilt core"))
        self.new.write_bytes(fake_elf(b"new independently rebuilt core"))
        # ELF checks are explicit and portable; tests do not depend on workstation architecture.
        self.original_arch = manager_module.platform.machine
        manager_module.platform.machine = lambda: "x86_64"

    def tearDown(self):
        manager_module.platform.machine = self.original_arch
        self.temp.cleanup()

    def install_old(self):
        self.manager.install(self.old, manager_module.digest(self.old))

    def config(self):
        return {"mode": "server", "transport": "tcpmux", "listen": "127.0.0.1:4000", "psk": "test-only-secret"}

    def test_checksum_rejection_precedes_install(self):
        with self.assertRaises(manager_module.ManagerError):
            self.manager.install(self.old, "0" * 64)
        self.assertFalse(self.manager.binary.exists())
        self.assertFalse(self.manager.state_path.exists())

    def test_original_vendor_brand_is_not_installed(self):
        self.manager.reject_brand = True
        with self.assertRaises(manager_module.ManagerError):
            self.manager.install(self.old, manager_module.digest(self.old))
        self.assertFalse(self.manager.binary.exists())

    def test_unowned_core_requires_exact_previous_digest(self):
        self.manager.binary.parent.mkdir(parents=True)
        self.manager.binary.write_bytes(self.old.read_bytes())
        with self.assertRaises(manager_module.ManagerError):
            self.manager.install(self.new, manager_module.digest(self.new), True, "0" * 64)
        self.assertEqual(self.manager.binary.read_bytes(), self.old.read_bytes())
        self.manager.install(self.new, manager_module.digest(self.new), True, manager_module.digest(self.old))
        self.assertEqual(self.manager.binary.read_bytes(), self.new.read_bytes())

    def test_invalid_config_does_not_replace_saved_config_or_unit(self):
        self.install_old()
        self.manager.create("demo", self.config())
        old_config = self.manager.config_path("demo").read_bytes()
        old_unit = self.manager.service_path("demo").read_bytes()
        old_state = self.manager.state_path.read_bytes()
        self.manager.fail_check = True
        with self.assertRaises(manager_module.ManagerError):
            self.manager.create("demo", {"unsupported": True}, replace=True)
        self.assertEqual(self.manager.config_path("demo").read_bytes(), old_config)
        self.assertEqual(self.manager.service_path("demo").read_bytes(), old_unit)
        self.assertEqual(self.manager.state_path.read_bytes(), old_state)

    def test_start_failure_rolls_back_core_hash_and_active_tunnel(self):
        self.install_old()
        self.manager.create("demo", self.config(), start=True)
        old_state = self.manager.state_path.read_bytes()
        self.manager.fail_start_once = True
        with self.assertRaises(manager_module.ManagerError):
            self.manager.install(self.new, manager_module.digest(self.new))
        self.assertEqual(self.manager.binary.read_bytes(), self.old.read_bytes())
        self.assertEqual(self.manager.state_path.read_bytes(), old_state)
        self.assertTrue(self.manager.service("is-active", "demo"))
        self.assertFalse(self.manager.path("/usr/local/bin/.netrix-rollback").exists())

    def test_failed_candidate_check_preserves_live_service(self):
        self.install_old()
        self.manager.create("demo", self.config(), start=True)
        event_file = self.manager.path("/var/lib/netrix-manager/simulation.json")
        previous_events = json.loads(event_file.read_text())["operations"]
        self.manager.fail_check = True
        with self.assertRaises(manager_module.ManagerError):
            self.manager.install(self.new, manager_module.digest(self.new))
        self.assertEqual(json.loads(event_file.read_text())["operations"], previous_events)
        self.assertTrue(self.manager.service("is-active", "demo"))

    def test_modified_unit_is_not_deleted_or_started(self):
        self.install_old()
        self.manager.create("demo", self.config())
        service = self.manager.service_path("demo")
        service.write_text("[Service]\nExecStart=/bin/true\n")
        for action in ("start", "delete", "restart", "stop"):
            with self.assertRaises(manager_module.ManagerError):
                self.manager.action(action, "demo")
        self.assertTrue(service.exists())

    def test_tunnel_id_cannot_inject_service_arguments(self):
        for value in ("../other", "demo;touch-file", "demo\nExecStart=/bin/sh", "demo.service", "-stop", "UPPER"):
            with self.assertRaises(manager_module.ManagerError):
                manager_module.tunnel_id(value)

    def test_config_payload_is_passed_as_data_never_service_shell(self):
        self.install_old()
        config = self.config()
        config["paths"] = [{"addr": "peer; echo unwanted\ncommand"}]
        self.manager.create("demo", config)
        service = self.manager.service_path("demo").read_text()
        self.assertNotIn("peer;", service)
        self.assertNotIn("/bin/sh", service)
        self.assertNotIn("LIC_CACHE", service)
        self.assertNotIn("unwanted", service)
        check_calls = [call for call in self.manager.checked if "-check" in call]
        self.assertTrue(check_calls)
        self.assertTrue(all(call[-1] == "-check" and len(call) == 3 for call in check_calls))

    def test_checksum_manifest_uses_exact_entry_and_rejects_duplicates(self):
        manifest = self.root / "SHA256SUMS"
        sha = manager_module.digest(self.old)
        manifest.write_text(f"{sha}  bin/netrix\n")
        self.assertEqual(manager_module.expected_digest(self.old, None, manifest, "bin/netrix"), sha)
        with self.assertRaises(manager_module.ManagerError):
            manager_module.expected_digest(self.old, None, manifest, "netrix")
        manifest.write_text(f"{sha}  bin/netrix\n{sha}  bin/netrix\n")
        with self.assertRaises(manager_module.ManagerError):
            manager_module.expected_digest(self.old, None, manifest, "bin/netrix")

    def test_generated_local_secrets_are_random_and_never_overwritten(self):
        first = self.manager.generate_secret("first").read_text().strip()
        second = self.manager.generate_secret("second").read_text().strip()
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertRegex(second, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)
        with self.assertRaises(manager_module.ManagerError):
            self.manager.generate_secret("first")
        self.assertEqual(self.manager.path("/etc/netrix/secrets/first.psk").read_text().strip(), first)

    def test_health_is_local_no_proxy_no_redirect_and_matches_core_port_priority(self):
        self.install_old()
        config = self.config()
        config.update({"transport": "l3", "health_port": 19080, "tun": {"health_port": 1234}})
        self.manager.create("demo", config)
        with patch.object(manager_module.urllib.request, "build_opener") as factory:
            factory.return_value.open.side_effect = lambda *args, **kwargs: io.BytesIO(b'{"sessions":0}')
            self.assertEqual(self.manager.health("demo"), {"sessions": 0})
            self.assertEqual(factory.return_value.open.call_args.args[0], "http://127.0.0.1:19080/health/detailed")
            handlers = factory.call_args.args
            self.assertTrue(any(isinstance(handler, manager_module.LocalHealthOnly) for handler in handlers))
            proxies = next(handler for handler in handlers if isinstance(handler, manager_module.urllib.request.ProxyHandler))
            self.assertEqual(proxies.proxies, {})
        config["health_port"] = 0
        self.manager.create("demo", config, replace=True)
        with patch.object(manager_module.urllib.request, "build_opener") as factory:
            factory.return_value.open.return_value = io.BytesIO(b'{"sessions":0}')
            self.manager.health("demo")
            self.assertEqual(factory.return_value.open.call_args.args[0], "http://127.0.0.1:1234/health/detailed")
        with self.assertRaises(manager_module.ManagerError):
            manager_module.LocalHealthOnly().redirect_request(None, None, 302, "redirect", {}, "https://example.invalid/status")

    def test_health_rejects_invalid_port_and_non_object_status(self):
        self.install_old()
        config = self.config()
        config.update({"health_port": 0, "tun": None})
        self.manager.create("demo", config)
        with patch.object(manager_module.urllib.request, "build_opener") as factory:
            with self.assertRaises(manager_module.ManagerError):
                self.manager.health("demo")
            factory.assert_not_called()
        config["health_port"] = True
        self.manager.create("demo", config, replace=True)
        with self.assertRaises(manager_module.ManagerError):
            self.manager.health("demo")
        config["health_port"] = 19080
        self.manager.create("demo", config, replace=True)
        with patch.object(manager_module.urllib.request, "build_opener") as factory:
            factory.return_value.open.return_value = io.BytesIO(b'[]')
            with self.assertRaises(manager_module.ManagerError):
                self.manager.health("demo")

    @unittest.skipUnless(hasattr(os, "symlink"), "Symbolic links unavailable")
    def test_symlink_config_directory_is_rejected(self):
        self.install_old()
        outside = self.root / "outside"
        outside.mkdir()
        config_dir = self.manager.path("/etc/netrix")
        config_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            config_dir.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Symbolic links require a platform privilege")
        with self.assertRaises(manager_module.ManagerError):
            self.manager.create("demo", self.config())
        self.assertEqual(list(outside.iterdir()), [])


class ManagerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="netrix-config-test-")
        self.root = Path(self.temp.name)
        self.psk = self.root / "peer.psk"
        self.psk.write_text("test-only-random-secret\n", encoding="ascii")

    def tearDown(self):
        self.temp.cleanup()

    def arguments(self, *extra):
        return manager_module.parser().parse_args(["create", "demo", "--mode", "client", "--peer", "192.0.2.1:4000",
                                                    "--psk-file", str(self.psk), *extra])

    def test_cli_all_transports_use_encryption_and_correct_scoped_fields(self):
        for transport in manager_module.TRANSPORTS:
            with self.subTest(transport=transport):
                args = self.arguments("--transport", transport, "--interface", "lab0", "--local-ip", "192.0.2.2", "--peer-ip", "192.0.2.1")
                config = manager_module.build_config(args)
                self.assertTrue(config["encryption"]["enabled"])
                self.assertEqual(config["psk"], "test-only-random-secret")
                if transport == "rawsocket":
                    self.assertEqual(config["rawsocket"]["local_ip"], "192.0.2.2")
                    self.assertEqual(config["rawsocket"]["router_mac"], "")
                elif transport == "l3":
                    self.assertTrue(config["l3"]["enable_encryption"])
                    self.assertEqual(config["tun"]["local"], "10.200.0.1/30")
                else:
                    self.assertEqual(config["paths"][0]["addr"], "192.0.2.1:4000")

    def test_explicit_plain_mode_and_tls_trust_fields(self):
        args = self.arguments("--transport", "tlsmux", "--no-encryption", "--ca", "/etc/netrix/certs/ca.pem", "--sni", "peer.internal")
        config = manager_module.build_config(args)
        self.assertFalse(config["encryption"]["enabled"])
        self.assertEqual(config["ca_file"], "/etc/netrix/certs/ca.pem")
        self.assertEqual(config["reality"]["sni"], "peer.internal")
        args = self.arguments("--transport", "l3", "--no-encryption", "--interface", "lab0", "--local-ip", "192.0.2.2", "--peer-ip", "192.0.2.1")
        self.assertFalse(manager_module.build_config(args)["l3"]["enable_encryption"])

    def test_import_preserves_operator_settings(self):
        imported = self.root / "config.json"
        settings = {"mode": "server", "encryption": {"enabled": False}, "custom_operator_field": [1, 2]}
        imported.write_text(json.dumps(settings), encoding="utf-8")
        args = manager_module.parser().parse_args(["create", "demo", "--config", str(imported)])
        self.assertEqual(manager_module.build_config(args), settings)

    def test_guided_setup_all_transports_emit_required_fields(self):
        for transport in manager_module.TRANSPORTS:
            for role in ("server", "client"):
                for connection in (("reverse",) if transport == "l3" else ("reverse", "direct")):
                    with self.subTest(transport=transport, role=role, connection=connection):
                        selections = iter(["1", "0"])
                        captured = []
                        local, peer = ("192.0.2.1", "192.0.2.2") if role == "server" else ("192.0.2.2", "192.0.2.1")

                        def answer(label, default=""):
                            if label == "Select":
                                return next(selections)
                            if label.startswith("Transport:"):
                                return transport
                            if "mappings; empty to skip" in label and role == "client":
                                self.fail("client setup must not request forwarding listeners")
                            values = {"Role: server/client": role, "Connection: reverse/direct": connection,
                                      "Physical interface": "lab0", "Local outer IPv4": local,
                                      "Peer outer IPv4": peer, "Local outer IP": local, "Peer outer IP": peer,
                                      "Peer address: HOST:PORT": peer + ":4000",
                                      "TCP mappings; empty to skip": "127.0.0.1:18080=127.0.0.1:8080",
                                      "UDP mappings; empty to skip": "127.0.0.1:18081=127.0.0.1:8081",
                                      "Existing certificate file": "/etc/netrix/certs/server.pem",
                                      "Existing private-key file": "/etc/netrix/certs/server.key"}
                            return values.get(label, default)

                        class WizardManager:
                            def create(self, name, config, **kwargs):
                                captured.append(config)

                        with patch.object(manager_module, "prompt", side_effect=answer), patch.object(manager_module.getpass, "getpass", return_value="test-only-secret"), patch("sys.stdout", new=io.StringIO()):
                            manager_module.wizard(WizardManager())
                        self.assertEqual(len(captured), 1)
                        config = captured[0]
                        self.assertEqual(config["mode"], role)
                        self.assertTrue(config["encryption"]["enabled"])
                        if role == "server":
                            self.assertEqual(config["tcp_ports"], ["127.0.0.1:18080=127.0.0.1:8080"])
                            self.assertEqual(config["udp_ports"], ["127.0.0.1:18081=127.0.0.1:8081"])
                        else:
                            self.assertEqual(config["tcp_ports"], [])
                            self.assertEqual(config["udp_ports"], [])
                        if transport == "l3":
                            # Client listeners would fail the core's L3 validation.
                            self.assertEqual(config["l3"]["listen_ip"], local)
                            self.assertEqual(config["l3"]["dst_ip"], peer)
                            self.assertEqual(config["tun"]["local"], "10.200.0.1/30" if role == "server" else "10.200.0.2/30")
                            self.assertEqual(config["tun"]["remote"], "10.200.0.2/30" if role == "server" else "10.200.0.1/30")
                        else:
                            self.assertEqual(config["direct"], connection == "direct")
                            listening = (role == "server") != (connection == "direct")
                            self.assertIn("listen" if listening else ("connect" if role == "server" else "paths"), config)
                            if transport == "rawsocket":
                                self.assertEqual(config["rawsocket"]["interface"], "lab0")
                            if transport in ("tlsmux", "wssmux", "realitymux") and listening:
                                self.assertIn("cert_file", config)
                                self.assertIn("key_file", config)


if __name__ == "__main__":
    unittest.main(verbosity=2)
