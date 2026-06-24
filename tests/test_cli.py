"""Tests for pyruijie.cli — WireGuard CLI commands."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pyruijie.cli import (
    EndpointUpdateResult,
    OnboardingResult,
    WireGuardSiteLink,
    _load_dotenv,
    _update_single_endpoint,
    build_parser,
    main,
)
from pyruijie.exceptions import (
    RuijieAuthError,
)

from .conftest import SAMPLE_CLIENT_POLICY, MockGatewayClient

# ── Structured result model tests ─────────────────────────────────────


class TestOnboardingResult:
    def test_success_summary(self):
        r = OnboardingResult(site_name="Test Site", success=True, peer_ip="10.0.0.50")
        assert "OK" in r.summary()
        assert "Test Site" in r.summary()

    def test_failure_summary(self):
        r = OnboardingResult(site_name="Bad Site", success=False, error="Connection refused")
        assert "FAILED" in r.summary()
        assert "Connection refused" in r.summary()

    def test_dry_run_summary(self):
        r = OnboardingResult(site_name="DR Site", success=True, dry_run=True, peer_ip="10.1.1.1")
        assert "DRY-RUN" in r.summary()

    def test_to_dict(self):
        r = OnboardingResult(
            site_name="Dict Site",
            success=True,
            peer_ip="10.1.1.1",
            steps=["step1", "step2"],
        )
        d = r.to_dict()
        assert d["site_name"] == "Dict Site"
        assert d["success"] is True
        assert len(d["steps"]) == 2


class TestEndpointUpdateResult:
    def test_to_dict(self):
        r = EndpointUpdateResult(ip="10.1.1.1", name="TestGW", success=True, action="updated")
        d = r.to_dict()
        assert d["ip"] == "10.1.1.1"
        assert d["success"] is True
        assert d["action"] == "updated"


class TestWireGuardSiteLink:
    def test_fields(self):
        link = WireGuardSiteLink(
            host="***REMOVED***",
            role="hub",
            peer_ip="10.0.0.50",
            pubkey="abc123==",
            policy_uuid="uuid-1",
            policy_name="WG_CLIENT",
        )
        assert link.role == "hub"
        assert link.peer_ip == "10.0.0.50"


# ── Parser tests ──────────────────────────────────────────────────────


class TestBuildParser:
    def test_parser_creates(self):
        parser = build_parser()
        assert parser is not None

    def test_peers_list(self):
        parser = build_parser()
        args = parser.parse_args(["peers", "list"])
        assert args.command == "peers"
        assert args.peers_action == "list"

    def test_peers_list_json(self):
        parser = build_parser()
        args = parser.parse_args(["peers", "list", "--json"])
        assert args.json is True

    def test_peers_add(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "peers",
                "add",
                "--desc",
                "Test Site",
                "--ip",
                "10.1.1.1",
                "--pubkey",
                "abc123==",
            ]
        )
        assert args.desc == "Test Site"
        assert args.ip == "10.1.1.1"
        assert args.pubkey == "abc123=="

    def test_peers_add_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "peers",
                "add",
                "--desc",
                "Test",
                "--ip",
                "10.1.1.1",
                "--pubkey",
                "k==",
                "--dry-run",
            ]
        )
        assert args.dry_run is True

    def test_peers_remove(self):
        parser = build_parser()
        args = parser.parse_args(["peers", "remove", "--ip", "10.1.1.1"])
        assert args.ip == "10.1.1.1"

    def test_peers_rename(self):
        parser = build_parser()
        args = parser.parse_args(["peers", "rename", "map.json"])
        assert args.map_file == "map.json"

    def test_probe(self):
        parser = build_parser()
        args = parser.parse_args(["probe", "10.0.0.105"])
        assert args.ip == "10.0.0.105"

    def test_update_endpoint(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "update-endpoint",
                "10.1.1.1",
                "10.1.1.2",
                "--new-endpoint",
                "example.com",
            ]
        )
        assert args.targets == ["10.1.1.1", "10.1.1.2"]
        assert args.new_endpoint == "example.com"

    def test_drift(self):
        parser = build_parser()
        args = parser.parse_args(["drift"])
        assert args.command == "drift"

    def test_drift_with_peer_ips(self):
        parser = build_parser()
        args = parser.parse_args(["drift", "--peer-ip", "10.1.1.1", "10.1.1.2"])
        assert args.peer_ip == ["10.1.1.1", "10.1.1.2"]

    def test_onboard_site(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "onboard-site",
                "--site-name",
                "Test Site",
                "--site-ip",
                "10.0.0.50",
                "--pubkey",
                "abc123==",
            ]
        )
        assert args.site_name == "Test Site"
        assert args.site_ip == "10.0.0.50"
        assert args.pubkey == "abc123=="

    def test_onboard_site_full(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "onboard-site",
                "--site-name",
                "Full Site",
                "--site-ip",
                "10.0.0.60",
                "--pubkey",
                "key==",
                "--peer-ip",
                "10.0.0.60",
                "--psk",
                "psk123==",
                "--configure-site",
                "--site-privkey",
                "privkey==",
                "--hub-endpoint",
                "hub.example.com",
                "--hub-port",
                "51821",
                "--policy-name",
                "MY_WG",
                "--dry-run",
                "-y",
            ]
        )
        assert args.configure_site is True
        assert args.site_privkey == "privkey=="
        assert args.hub_endpoint == "hub.example.com"
        assert args.hub_port == "51821"
        assert args.policy_name == "MY_WG"
        assert args.dry_run is True
        assert args.yes is True

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["-v", "peers", "list"])
        assert args.verbose is True

    def test_env_file_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--env-file", "/tmp/.env", "peers", "list"])
        assert args.env_file == "/tmp/.env"


# ── dotenv loader tests ───────────────────────────────────────────────


class TestLoadDotenv:
    def test_loads_env_file(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("TEST_CLI_VAR=hello\n# comment\nTEST_CLI_VAR2=world\n")
        os.environ.pop("TEST_CLI_VAR", None)
        os.environ.pop("TEST_CLI_VAR2", None)

        _load_dotenv(env)
        assert os.environ.get("TEST_CLI_VAR") == "hello"
        assert os.environ.get("TEST_CLI_VAR2") == "world"

        # Cleanup
        os.environ.pop("TEST_CLI_VAR", None)
        os.environ.pop("TEST_CLI_VAR2", None)

    def test_does_not_override(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("TEST_CLI_NOOVERRIDE=new\n")
        os.environ["TEST_CLI_NOOVERRIDE"] = "old"

        _load_dotenv(env)
        assert os.environ["TEST_CLI_NOOVERRIDE"] == "old"

        os.environ.pop("TEST_CLI_NOOVERRIDE", None)

    def test_missing_file(self):
        _load_dotenv(Path("/nonexistent/.env"))
        # Should not raise

    def test_none_with_no_file(self):
        _load_dotenv(None)
        # Should not raise


# ── peers list command tests ──────────────────────────────────────────


class TestPeersList:
    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_list_text_output(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        gw = MockGatewayClient()
        mock_connect.return_value = gw

        main(["peers", "list"])

        out = capsys.readouterr().out
        assert "Site Alpha" in out
        assert "10.100.0.105" in out
        assert "Peers: 3" in out

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_list_json_output(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        gw = MockGatewayClient()
        mock_connect.return_value = gw

        main(["peers", "list", "--json"])

        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 3
        assert any(p["desc"] == "Site Alpha" for p in data)


# ── peers add command tests ───────────────────────────────────────────


class TestPeersAdd:
    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_add_dry_run(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")

        main(
            [
                "peers",
                "add",
                "--desc",
                "New Site",
                "--ip",
                "10.0.0.200",
                "--pubkey",
                "NEWKEY==",
                "--dry-run",
            ]
        )

        out = capsys.readouterr().out
        assert "DRY-RUN" in out
        assert "New Site" in out
        # Gateway should not be connected in dry-run
        mock_connect.assert_not_called()

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_add_with_yes(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        gw = MockGatewayClient()
        mock_connect.return_value = gw

        main(
            [
                "peers",
                "add",
                "--desc",
                "New Site",
                "--ip",
                "10.0.0.200",
                "--pubkey",
                "NEWPUBKEY123==",
                "-y",
            ]
        )

        out = capsys.readouterr().out
        assert "OK" in out
        assert "New Site" in out


# ── peers remove command tests ────────────────────────────────────────


class TestPeersRemove:
    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_remove_dry_run(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")

        main(["peers", "remove", "--ip", "10.0.0.105", "--dry-run"])

        out = capsys.readouterr().out
        assert "DRY-RUN" in out
        mock_connect.assert_not_called()

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_remove_with_yes(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        gw = MockGatewayClient()
        mock_connect.return_value = gw

        main(["peers", "remove", "--ip", "10.100.0.105", "-y"])

        out = capsys.readouterr().out
        assert "OK" in out
        assert "Removed" in out


# ── peers rename command tests ────────────────────────────────────────


class TestPeersRename:
    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_rename_dry_run(self, mock_dotenv, mock_creds, mock_connect, capsys, tmp_path):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")

        map_file = tmp_path / "rename_map.json"
        map_file.write_text(json.dumps({"laptop-Danny": "Danny Personal Laptop"}))

        main(["peers", "rename", str(map_file), "--dry-run"])

        out = capsys.readouterr().out
        assert "DRY-RUN" in out
        assert "laptop-Danny" in out

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_rename_apply(self, mock_dotenv, mock_creds, mock_connect, capsys, tmp_path):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        gw = MockGatewayClient()
        mock_connect.return_value = gw

        map_file = tmp_path / "rename_map.json"
        map_file.write_text(json.dumps({"laptop-user1": "Danny Laptop"}))

        main(["peers", "rename", str(map_file), "-y"])

        out = capsys.readouterr().out
        assert "OK" in out
        assert "Renamed 1" in out


# ── probe command tests ───────────────────────────────────────────────


class TestProbe:
    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._load_dotenv")
    def test_probe_text(self, mock_dotenv, mock_connect, capsys, monkeypatch):
        # cmd_probe reads the gateway password from the environment directly.
        monkeypatch.setenv("UNIQUE_GW_PASSWORD", "pass")
        gw = MockGatewayClient(host="10.0.0.105")
        gw.serial_number = "GW123456"
        mock_connect.return_value = gw

        main(["probe", "10.0.0.105"])

        out = capsys.readouterr().out
        assert "10.0.0.105" in out
        assert "Client policies:" in out


# ── update-endpoint command tests ─────────────────────────────────────


class TestUpdateEndpoint:
    def test_update_single_endpoint_already_configured(self):
        mock_gw = MockGatewayClient(host="10.0.0.105")
        # The mock client policy has endpoint "198.51.100.1"
        with patch("pyruijie.cli._connect_gateway", return_value=mock_gw):
            r = _update_single_endpoint(
                ip="10.0.0.105",
                name="TestGW",
                new_endpoint="198.51.100.1",
                old_endpoint=None,
                username="admin",
                password="pass",
                dry_run=False,
            )
        assert r.success is True
        assert r.action == "already_configured"

    def test_update_single_endpoint_needs_update_dry_run(self):
        mock_gw = MockGatewayClient(host="10.0.0.105")
        with patch("pyruijie.cli._connect_gateway", return_value=mock_gw):
            r = _update_single_endpoint(
                ip="10.0.0.105",
                name="TestGW",
                new_endpoint="new.endpoint.com",
                old_endpoint=None,
                username="admin",
                password="pass",
                dry_run=True,
            )
        assert r.success is True
        assert r.action == "needs_update"

    def test_update_single_endpoint_wrong_old_endpoint(self):
        mock_gw = MockGatewayClient(host="10.0.0.105")
        with patch("pyruijie.cli._connect_gateway", return_value=mock_gw):
            r = _update_single_endpoint(
                ip="10.0.0.105",
                name="TestGW",
                new_endpoint="new.endpoint.com",
                old_endpoint="wrong.old.endpoint",
                username="admin",
                password="pass",
                dry_run=False,
            )
        assert r.success is False
        assert "Unexpected endpoint" in r.error

    def test_update_single_endpoint_login_failure(self):
        with patch("pyruijie.cli._connect_gateway", side_effect=RuijieAuthError("Login failed")):
            r = _update_single_endpoint(
                ip="10.0.0.105",
                name="TestGW",
                new_endpoint="new.endpoint.com",
                old_endpoint=None,
                username="admin",
                password="pass",
                dry_run=False,
            )
        assert r.success is False
        assert "Login failed" in r.error

    def test_update_single_endpoint_applies(self):
        mock_gw = MockGatewayClient(host="10.0.0.105")
        with patch("pyruijie.cli._connect_gateway", return_value=mock_gw):
            r = _update_single_endpoint(
                ip="10.0.0.105",
                name="TestGW",
                new_endpoint="new.endpoint.com",
                old_endpoint="198.51.100.1",
                username="admin",
                password="pass",
                dry_run=False,
            )
        assert r.success is True
        assert r.action == "updated"


# ── onboard-site command tests ────────────────────────────────────────


class TestOnboardSite:
    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_onboard_dry_run(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        hub_gw = MockGatewayClient()
        mock_connect.return_value = hub_gw

        main(
            [
                "onboard-site",
                "--site-name",
                "Test Site",
                "--site-ip",
                "10.0.0.50",
                "--pubkey",
                "TESTKEY==",
                "--peer-ip",
                "10.0.0.200",
                "--dry-run",
            ]
        )

        out = capsys.readouterr().out
        assert "DRY-RUN" in out
        assert "Test Site" in out

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_onboard_add_peer(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        hub_gw = MockGatewayClient()
        mock_connect.return_value = hub_gw

        main(
            [
                "onboard-site",
                "--site-name",
                "New Site",
                "--site-ip",
                "10.0.0.50",
                "--pubkey",
                "NEWSITEKEY==",
                "--peer-ip",
                "10.0.0.200",
                "-y",
            ]
        )

        out = capsys.readouterr().out
        assert "OK" in out
        assert "Hub peer added" in out

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_onboard_existing_peer_idempotent(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        hub_gw = MockGatewayClient()
        mock_connect.return_value = hub_gw

        # Use an IP that already exists in the mock
        main(
            [
                "onboard-site",
                "--site-name",
                "Existing",
                "--site-ip",
                "10.0.0.50",
                "--pubkey",
                "KEY==",
                "--peer-ip",
                "10.100.0.105",
                "-y",
            ]
        )

        out = capsys.readouterr().out
        assert "already exists" in out

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_onboard_with_output_file(
        self, mock_dotenv, mock_creds, mock_connect, capsys, tmp_path
    ):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        hub_gw = MockGatewayClient()
        mock_connect.return_value = hub_gw

        out_file = tmp_path / "result.json"

        main(
            [
                "onboard-site",
                "--site-name",
                "Output Test",
                "--site-ip",
                "10.0.0.50",
                "--pubkey",
                "KEY==",
                "--peer-ip",
                "10.0.0.201",
                "-y",
                "-o",
                str(out_file),
            ]
        )

        assert out_file.exists()
        result = json.loads(out_file.read_text())
        assert result["site_name"] == "Output Test"
        assert result["success"] is True

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_onboard_conflict_error(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        hub_gw = MockGatewayClient()
        mock_connect.return_value = hub_gw

        # Try to add a peer with an IP that already exists (different pubkey)
        # The WireGuardManager.add_site_peer will check for conflicts
        main(
            [
                "onboard-site",
                "--site-name",
                "Conflict Site",
                "--site-ip",
                "10.0.0.50",
                "--pubkey",
                "DIFFERENTKEY==",
                "--peer-ip",
                "10.100.0.105",
                "-y",
            ]
        )

        out = capsys.readouterr().out
        # Should be handled gracefully — the peer already exists
        assert "already exists" in out


# ── drift command tests ───────────────────────────────────────────────


class TestDrift:
    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_drift_detects_in_sync(self, mock_dotenv, mock_creds, mock_connect, capsys):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")

        hub_gw = MockGatewayClient()
        site_gw = MockGatewayClient(
            host="10.0.0.105",
            client_policy=SAMPLE_CLIENT_POLICY,
        )

        call_count = {"n": 0}

        def connect_side_effect(host, user, pw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return hub_gw
            return site_gw

        mock_connect.side_effect = connect_side_effect

        main(["drift", "--peer-ip", "10.100.0.105"])

        out = capsys.readouterr().out
        assert "1 peers checked" in out


# ── main() integration tests ──────────────────────────────────────────


class TestMainEntry:
    def test_help(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0

    def test_peers_help(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["peers", "--help"])
        assert exc.value.code == 0

    def test_no_command_exits(self):
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code != 0

    @patch("pyruijie.cli._connect_gateway")
    @patch("pyruijie.cli._hub_credentials")
    @patch("pyruijie.cli._load_dotenv")
    def test_verbose_enables_logging(self, mock_dotenv, mock_creds, mock_connect):
        mock_creds.return_value = ("***REMOVED***", "admin", "pass")
        gw = MockGatewayClient()
        mock_connect.return_value = gw

        with patch("logging.basicConfig") as mock_log:
            main(["-v", "peers", "list"])
            mock_log.assert_called_once()

    @patch("pyruijie.cli._load_dotenv")
    def test_env_file_flag(self, mock_dotenv):
        mock_creds = ("***REMOVED***", "admin", "pass")
        with (
            patch("pyruijie.cli._hub_credentials", return_value=mock_creds),
            patch("pyruijie.cli._connect_gateway", return_value=MockGatewayClient()),
        ):
            main(["--env-file", "/tmp/test.env", "peers", "list"])
        # _load_dotenv called twice: once in main() with Path, once from cmd
        # The explicit env-file path should be used


# ── _confirm helper tests ─────────────────────────────────────────────


class TestConfirm:
    def test_confirm_yes(self):
        from pyruijie.cli import _confirm

        with patch("builtins.input", return_value="y"):
            _confirm("test?")  # Should not raise

    def test_confirm_no_exits(self):
        from pyruijie.cli import _confirm

        with patch("builtins.input", return_value="n"), pytest.raises(SystemExit):
            _confirm("test?")

    def test_confirm_eof_exits(self):
        from pyruijie.cli import _confirm

        with patch("builtins.input", side_effect=EOFError), pytest.raises(SystemExit):
            _confirm("test?")

    def test_confirm_keyboard_interrupt_exits(self):
        from pyruijie.cli import _confirm

        with patch("builtins.input", side_effect=KeyboardInterrupt), pytest.raises(SystemExit):
            _confirm("test?")
