"""Hermetic tests for the Bitwarden Vault (`bw` CLI) integration.

We never hit GitHub or Bitwarden in tests — subprocess and urllib are
mocked so the suite stays fast and offline-safe.  The key difference
from the BSM (bws) tests is that `bw` requires a multi-step session
handshake: status → unlock → sync → list folders → list items.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.secret_sources import bitwarden_vault as bv  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bw_status_payload(status: str = "unlocked") -> str:
    return json.dumps({"status": status, "userEmail": "user@example.com"})


def _bw_folders_payload(folders: list | None = None) -> str:
    if folders is None:
        folders = [{"id": "folder-uuid-1", "name": "hermes"}]
    return json.dumps(folders)


def _bw_items_payload(items: list | None = None) -> str:
    if items is None:
        items = [
            {
                "id": "item-uuid-1",
                "name": "OPENAI_API_KEY",
                "type": 1,
                "login": {"password": "sk-abc"},
            },
            {
                "id": "item-uuid-2",
                "name": "ANTHROPIC_API_KEY",
                "type": 2,
                "notes": "sk-ant-xyz",
            },
        ]
    return json.dumps(items)


def _make_fake_bw_zip(binary_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bw", binary_bytes)
    return buf.getvalue()


class FakeBwRunner:
    """Simulates the `bw` CLI subprocess for the full session lifecycle."""

    def __init__(
        self,
        *,
        status: str = "locked",
        session_token: str = "fake-session-token",
        folders: list | None = None,
        items: list | None = None,
        unlock_fail: bool = False,
        sync_fail: bool = False,
    ):
        self.status = status
        self.session_token = session_token
        self.folders = folders
        self.items = items
        self.unlock_fail = unlock_fail
        self.sync_fail = sync_fail
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        cmd_args = [str(a) for a in cmd]

        if "status" in cmd_args:
            return mock.Mock(
                returncode=0, stdout=_bw_status_payload(self.status), stderr=""
            )

        if "unlock" in cmd_args:
            if self.unlock_fail:
                return mock.Mock(
                    returncode=1, stdout="", stderr="Invalid master password"
                )
            return mock.Mock(returncode=0, stdout=self.session_token, stderr="")

        if "sync" in cmd_args:
            if self.sync_fail:
                return mock.Mock(returncode=1, stdout="", stderr="Sync failed")
            return mock.Mock(returncode=0, stdout="", stderr="")

        if "folders" in cmd_args:
            return mock.Mock(
                returncode=0,
                stdout=_bw_folders_payload(self.folders),
                stderr="",
            )

        if "items" in cmd_args:
            return mock.Mock(
                returncode=0,
                stdout=_bw_items_payload(self.items),
                stderr="",
            )

        return mock.Mock(returncode=0, stdout="", stderr="")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_caches():
    bv._reset_cache_for_tests()
    yield
    bv._reset_cache_for_tests()


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    import hermes_constants

    if hasattr(hermes_constants, "_HERMES_HOME_CACHE"):
        hermes_constants._HERMES_HOME_CACHE = None  # type: ignore[attr-defined]
    return home


@pytest.fixture
def fake_binary(tmp_path):
    binary = tmp_path / "bw"
    binary.write_text("#!/bin/sh\necho fake bw\n")
    binary.chmod(0o755)
    return binary


# ---------------------------------------------------------------------------
# _platform_asset_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "system,expected",
    [
        ("Darwin", f"bw-macos-{bv._BW_VERSION}.zip"),
        ("Linux", f"bw-linux-{bv._BW_VERSION}.zip"),
        ("Windows", f"bw-windows-{bv._BW_VERSION}.zip"),
    ],
)
def test_platform_asset_name(system, expected):
    with mock.patch.object(bv.platform, "system", return_value=system):
        assert bv._platform_asset_name() == expected


def test_platform_asset_name_unsupported():
    with mock.patch.object(bv.platform, "system", return_value="FreeBSD"):
        with pytest.raises(RuntimeError, match="Unsupported platform"):
            bv._platform_asset_name()


# ---------------------------------------------------------------------------
# install_bw — fully mocked HTTP
# ---------------------------------------------------------------------------


def test_install_bw_happy_path(hermes_home, monkeypatch):
    fake_binary_bytes = b"#!/bin/sh\necho 'bw fake'\n"
    zip_bytes = _make_fake_bw_zip(fake_binary_bytes)
    asset_name = bv._platform_asset_name()
    checksum_text = (
        f"{hashlib.sha256(zip_bytes).hexdigest()}  {asset_name}\n"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  other\n"
    )

    def fake_download(url, dest):
        if url.endswith(".zip"):
            Path(dest).write_bytes(zip_bytes)
        elif url.endswith(".txt"):
            Path(dest).write_text(checksum_text)
        else:
            raise AssertionError(f"unexpected download url: {url}")

    monkeypatch.setattr(bv, "_http_download", fake_download)

    path = bv.install_bw()
    assert path.exists()
    assert path.read_bytes() == fake_binary_bytes
    assert path.stat().st_mode & stat.S_IXUSR


def test_install_bw_checksum_mismatch(hermes_home, monkeypatch):
    zip_bytes = _make_fake_bw_zip(b"contents")
    asset_name = bv._platform_asset_name()
    checksum_text = f"{'0' * 64}  {asset_name}\n"

    def fake_download(url, dest):
        if url.endswith(".zip"):
            Path(dest).write_bytes(zip_bytes)
        else:
            Path(dest).write_text(checksum_text)

    monkeypatch.setattr(bv, "_http_download", fake_download)

    with pytest.raises(RuntimeError, match="Checksum mismatch"):
        bv.install_bw()


def test_install_bw_no_checksum_entry(hermes_home, monkeypatch):
    zip_bytes = _make_fake_bw_zip(b"x")

    def fake_download(url, dest):
        if url.endswith(".zip"):
            Path(dest).write_bytes(zip_bytes)
        else:
            Path(dest).write_text("ffffffff  completely-different-file.zip\n")

    monkeypatch.setattr(bv, "_http_download", fake_download)

    with pytest.raises(RuntimeError, match="No checksum entry"):
        bv.install_bw()


def test_install_bw_skips_when_already_present(hermes_home, monkeypatch):
    """Second install call is a no-op (no HTTP downloads)."""
    bin_dir = hermes_home / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    existing = bin_dir / bv._platform_binary_name()
    existing.write_bytes(b"existing binary")
    existing.chmod(0o755)

    download_called = {"n": 0}

    def fake_download(url, dest):
        download_called["n"] += 1

    monkeypatch.setattr(bv, "_http_download", fake_download)
    result = bv.install_bw()
    assert result == existing
    assert download_called["n"] == 0


# ---------------------------------------------------------------------------
# Password storage helpers
# ---------------------------------------------------------------------------


def test_read_from_file(tmp_path):
    home = tmp_path / ".hermes"
    home.mkdir()
    pw_file = home / bv._PASSWORD_FILE_NAME
    pw_file.write_text("super-secret\n")
    pw_file.chmod(0o600)

    result = bv._read_from_file(home)
    assert result == "super-secret"


def test_read_from_file_missing(tmp_path):
    home = tmp_path / ".hermes"
    home.mkdir()
    assert bv._read_from_file(home) is None


def test_write_to_file_mode(tmp_path):
    home = tmp_path / ".hermes"
    home.mkdir()
    path = bv._write_to_file("my-password", home)
    assert path.exists()
    assert path.read_text(encoding="utf-8") == "my-password"
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0o600, got 0o{mode:o}"


def test_store_master_password_file_fallback(tmp_path, monkeypatch):
    """When keyring is unavailable, store_master_password falls back to file."""
    home = tmp_path / ".hermes"
    home.mkdir()

    monkeypatch.setattr(bv, "_write_to_keyring", lambda email, pw: False)

    method = bv.store_master_password(
        "user@example.com", "pw123", password_storage="auto", home_path=home
    )
    assert method == "file"
    assert (home / bv._PASSWORD_FILE_NAME).exists()


def test_store_master_password_keyring_success(monkeypatch):
    monkeypatch.setattr(bv, "_write_to_keyring", lambda email, pw: True)

    method = bv.store_master_password(
        "user@example.com", "pw123", password_storage="auto"
    )
    assert method == "keyring"


# ---------------------------------------------------------------------------
# _extract_secret_value
# ---------------------------------------------------------------------------


def test_extract_login_item():
    item = {"type": 1, "login": {"password": "secret123"}}
    assert bv._extract_secret_value(item) == "secret123"


def test_extract_secure_note():
    item = {"type": 2, "notes": "note-value"}
    assert bv._extract_secret_value(item) == "note-value"


def test_extract_unsupported_type():
    item = {"type": 3, "card": {}}
    assert bv._extract_secret_value(item) is None


def test_extract_login_no_password():
    item = {"type": 1, "login": {}}
    assert bv._extract_secret_value(item) is None


# ---------------------------------------------------------------------------
# fetch_vault_secrets — the main fetch path
# ---------------------------------------------------------------------------


def test_fetch_happy_path(monkeypatch, tmp_path, hermes_home):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner(status="locked")

    monkeypatch.setattr(bv.subprocess, "run", runner)
    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "master-pw")
    # _get_session_token writes a temp password file; mock _run_bw too
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )

    secrets, warnings = bv.fetch_vault_secrets(
        email="user@example.com",
        folder_name="hermes",
        binary=fake_bin,
        use_cache=False,
    )
    assert secrets.get("OPENAI_API_KEY") == "sk-abc"
    assert secrets.get("ANTHROPIC_API_KEY") == "sk-ant-xyz"
    assert warnings == []


def test_fetch_empty_email_raises():
    with pytest.raises(RuntimeError, match="email is empty"):
        bv.fetch_vault_secrets(email="", use_cache=False, binary=Path("/fake/bw"))


def test_fetch_folder_not_found(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner(folders=[{"id": "f1", "name": "other-folder"}])

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )
    monkeypatch.setattr(bv.subprocess, "run", runner)

    with pytest.raises(RuntimeError, match="Folder 'hermes' not found"):
        bv.fetch_vault_secrets(
            email="user@example.com",
            folder_name="hermes",
            binary=fake_bin,
            use_cache=False,
        )


def test_fetch_skips_invalid_env_names(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    bad_items = [
        {"id": "i1", "name": "VALID_KEY", "type": 1, "login": {"password": "v1"}},
        {"id": "i2", "name": "1INVALID", "type": 1, "login": {"password": "v2"}},
        {"id": "i3", "name": "has spaces", "type": 1, "login": {"password": "v3"}},
        {"id": "i4", "name": "DASH-KEY", "type": 1, "login": {"password": "v4"}},
    ]
    runner = FakeBwRunner(items=bad_items)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )
    monkeypatch.setattr(bv.subprocess, "run", runner)

    secrets, warnings = bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        use_cache=False,
    )
    assert secrets == {"VALID_KEY": "v1"}
    assert len(warnings) == 3


def test_fetch_skips_items_with_no_value(monkeypatch, tmp_path):
    """Items whose type is unsupported or have no extractable value are skipped."""
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    items = [
        {"id": "i1", "name": "GOOD_KEY", "type": 1, "login": {"password": "ok"}},
        {"id": "i2", "name": "CARD_KEY", "type": 3, "card": {}},  # unsupported type
        {"id": "i3", "name": "EMPTY_NOTE", "type": 2, "notes": None},
    ]
    runner = FakeBwRunner(items=items)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )
    monkeypatch.setattr(bv.subprocess, "run", runner)

    secrets, warnings = bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        use_cache=False,
    )
    assert secrets == {"GOOD_KEY": "ok"}
    assert len(warnings) == 2


def test_fetch_unlock_failure(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner(unlock_fail=True)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "wrong-pw")
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )
    monkeypatch.setattr(bv.subprocess, "run", runner)

    with pytest.raises(RuntimeError, match="bw unlock failed"):
        bv.fetch_vault_secrets(
            email="user@example.com",
            binary=fake_bin,
            use_cache=False,
        )


def test_fetch_missing_password(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: None)
    monkeypatch.setattr(
        bv.subprocess,
        "run",
        lambda *a, **kw: mock.Mock(
            returncode=0, stdout=_bw_status_payload("locked"), stderr=""
        ),
    )

    with pytest.raises(RuntimeError, match="Master password not found"):
        bv.fetch_vault_secrets(
            email="user@example.com",
            binary=fake_bin,
            use_cache=False,
        )


def test_fetch_in_process_cache_hit(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner()
    call_counts = {"unlock": 0}

    original_run_bw = bv._run_bw

    def counting_run_bw(bw_bin, args, **kw):
        if "unlock" in args:
            call_counts["unlock"] += 1
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", counting_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", runner)

    bv.fetch_vault_secrets(
        email="user@example.com", binary=fake_bin, cache_ttl_seconds=60
    )
    bv.fetch_vault_secrets(
        email="user@example.com", binary=fake_bin, cache_ttl_seconds=60
    )
    assert call_counts["unlock"] == 1  # second call hit in-process cache


def test_fetch_cache_keyed_by_folder(monkeypatch, tmp_path):
    """Different folder names produce separate cache entries."""
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    unlock_calls = {"n": 0}

    def counting_run_bw(bw_bin, args, **kw):
        runner = FakeBwRunner(
            folders=[
                {"id": "f1", "name": "hermes"},
                {"id": "f2", "name": "other"},
            ]
        )
        if "unlock" in args:
            unlock_calls["n"] += 1
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", counting_run_bw)
    monkeypatch.setattr(
        bv.subprocess,
        "run",
        FakeBwRunner(
            folders=[
                {"id": "f1", "name": "hermes"},
                {"id": "f2", "name": "other"},
            ]
        ),
    )

    bv.fetch_vault_secrets(
        email="user@example.com",
        folder_name="hermes",
        binary=fake_bin,
        cache_ttl_seconds=60,
    )
    bv.fetch_vault_secrets(
        email="user@example.com",
        folder_name="other",
        binary=fake_bin,
        cache_ttl_seconds=60,
    )
    bv.fetch_vault_secrets(
        email="user@example.com",
        folder_name="other",
        binary=fake_bin,
        cache_ttl_seconds=60,
    )
    # hermes + other = 2 fetches; third call hits cache
    assert unlock_calls["n"] == 2


# ---------------------------------------------------------------------------
# _get_session_token — unauthenticated guard
# ---------------------------------------------------------------------------


def test_get_session_unauthenticated(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv, "_check_status", lambda bw_bin, tls_env=None: {"status": "unauthenticated"}
    )
    monkeypatch.setattr(bv, "_configure_server", lambda *a, **kw: None)

    with pytest.raises(RuntimeError, match="Not logged in"):
        bv._get_session_token(fake_bin, "user@example.com")


# ---------------------------------------------------------------------------
# _run_bw — timeout + OSError handling
# ---------------------------------------------------------------------------


def test_run_bw_timeout(tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    with mock.patch.object(
        bv.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(cmd="bw", timeout=30),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            bv._run_bw(fake_bin, ["unlock"])


def test_run_bw_oserror(tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    with mock.patch.object(bv.subprocess, "run", side_effect=OSError("no such file")):
        with pytest.raises(RuntimeError, match="failed to invoke bw"):
            bv._run_bw(fake_bin, ["unlock"])


# ---------------------------------------------------------------------------
# apply_vault_secrets — the public entry point
# ---------------------------------------------------------------------------


def test_apply_disabled_returns_empty():
    result = bv.apply_vault_secrets(enabled=False, email="user@example.com")
    assert result.ok
    assert not result.applied
    assert not result.error


def test_apply_missing_email():
    result = bv.apply_vault_secrets(enabled=True, email="", auto_install=False)
    assert not result.ok
    assert "email" in result.error


def test_apply_no_binary(monkeypatch):
    monkeypatch.setattr(bv, "find_bw", lambda **kw: None)
    result = bv.apply_vault_secrets(
        enabled=True, email="user@example.com", auto_install=False
    )
    assert not result.ok
    assert "bw binary" in result.error


def test_apply_does_not_override_existing(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "existing-value")
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    items = [
        {
            "id": "i1",
            "name": "OPENAI_API_KEY",
            "type": 1,
            "login": {"password": "vault-value"},
        },
        {"id": "i2", "name": "NEW_KEY", "type": 1, "login": {"password": "new-value"}},
    ]
    runner = FakeBwRunner(items=items)

    monkeypatch.setattr(bv, "find_bw", lambda **kw: fake_bin)
    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )
    monkeypatch.setattr(bv.subprocess, "run", runner)

    result = bv.apply_vault_secrets(
        enabled=True,
        email="user@example.com",
        override_existing=False,
        auto_install=False,
    )
    assert result.ok
    assert "NEW_KEY" in result.applied
    assert "OPENAI_API_KEY" in result.skipped
    assert os.environ["OPENAI_API_KEY"] == "existing-value"
    assert os.environ["NEW_KEY"] == "new-value"


def test_apply_override_existing(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "stale")
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    items = [
        {
            "id": "i1",
            "name": "OPENAI_API_KEY",
            "type": 1,
            "login": {"password": "fresh"},
        },
    ]
    runner = FakeBwRunner(items=items)

    monkeypatch.setattr(bv, "find_bw", lambda **kw: fake_bin)
    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )
    monkeypatch.setattr(bv.subprocess, "run", runner)

    result = bv.apply_vault_secrets(
        enabled=True,
        email="user@example.com",
        override_existing=True,
        auto_install=False,
    )
    assert result.ok
    assert os.environ["OPENAI_API_KEY"] == "fresh"


def test_apply_swallows_fetch_errors(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    monkeypatch.setattr(bv, "find_bw", lambda **kw: fake_bin)
    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv,
        "_run_bw",
        lambda bw_bin, args, **kw: mock.Mock(
            returncode=1, stdout="", stderr="Vault is locked"
        ),
    )
    monkeypatch.setattr(
        bv.subprocess,
        "run",
        lambda *a, **kw: mock.Mock(
            returncode=0, stdout=_bw_status_payload("locked"), stderr=""
        ),
    )

    result = bv.apply_vault_secrets(
        enabled=True, email="user@example.com", auto_install=False
    )
    assert not result.ok
    assert result.error  # some error message set


# ---------------------------------------------------------------------------
# Disk-persisted cache
# ---------------------------------------------------------------------------


def test_disk_cache_written_after_first_fetch(monkeypatch, tmp_path):
    home = tmp_path / ".hermes"
    home.mkdir()
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner()
    bv._reset_cache_for_tests(home)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(
        bv, "_run_bw", lambda bw_bin, args, **kw: runner([str(bw_bin)] + args)
    )
    monkeypatch.setattr(bv.subprocess, "run", runner)

    secrets, _ = bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        cache_ttl_seconds=300,
        home_path=home,
    )
    assert "OPENAI_API_KEY" in secrets

    cache_path = bv._disk_cache_path(home)
    assert cache_path.exists()
    mode = os.stat(cache_path).st_mode & 0o777
    assert mode == 0o600, f"expected 0o600, got 0o{mode:o}"

    payload_disk = json.loads(cache_path.read_text())
    assert set(payload_disk.keys()) == {"key", "secrets", "fetched_at"}
    # Email fingerprint, not the raw email, should be in the key
    assert "user@example.com" not in payload_disk["key"]


def test_disk_cache_short_circuits_bw_when_fresh(monkeypatch, tmp_path):
    home = tmp_path / ".hermes"
    home.mkdir()
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    unlock_calls = {"n": 0}

    def counting_run_bw(bw_bin, args, **kw):
        runner = FakeBwRunner()
        if "unlock" in args:
            unlock_calls["n"] += 1
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", counting_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", FakeBwRunner())
    bv._reset_cache_for_tests(home)

    bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        cache_ttl_seconds=300,
        home_path=home,
    )
    assert unlock_calls["n"] == 1

    # Simulate a new process by clearing the in-process cache
    bv._CACHE.clear()

    bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        cache_ttl_seconds=300,
        home_path=home,
    )
    assert unlock_calls["n"] == 1  # disk cache was used


def test_disk_cache_expires_with_ttl(monkeypatch, tmp_path):
    home = tmp_path / ".hermes"
    home.mkdir()
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")

    unlock_calls = {"n": 0}

    def counting_run_bw(bw_bin, args, **kw):
        runner = FakeBwRunner()
        if "unlock" in args:
            unlock_calls["n"] += 1
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", counting_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", FakeBwRunner())
    bv._reset_cache_for_tests(home)

    bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        cache_ttl_seconds=300,
        home_path=home,
    )
    assert unlock_calls["n"] == 1

    # Backdate the disk cache to expire the TTL
    cache_path = bv._disk_cache_path(home)
    payload_disk = json.loads(cache_path.read_text())
    payload_disk["fetched_at"] = time.time() - 10_000
    cache_path.write_text(json.dumps(payload_disk))
    bv._CACHE.clear()

    bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        cache_ttl_seconds=300,
        home_path=home,
    )
    assert unlock_calls["n"] == 2  # stale disk cache → refetch


# ---------------------------------------------------------------------------
# _tls_env_vars
# ---------------------------------------------------------------------------


def test_tls_env_vars_empty():
    assert bv._tls_env_vars() == {}


def test_tls_env_vars_ca_cert(tmp_path):
    pem = tmp_path / "ca.pem"
    pem.write_text("cert")
    result = bv._tls_env_vars(ca_cert=str(pem))
    assert result == {"NODE_EXTRA_CA_CERTS": str(pem)}


def test_tls_env_vars_insecure():
    result = bv._tls_env_vars(insecure_tls=True)
    assert result == {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}


def test_tls_env_vars_use_system_ca():
    result = bv._tls_env_vars(use_system_ca=True)
    assert result == {"NODE_OPTIONS": "--use-system-ca"}


def test_tls_env_vars_ca_cert_and_use_system_ca(tmp_path):
    pem = tmp_path / "ca.pem"
    pem.write_text("cert")
    result = bv._tls_env_vars(ca_cert=str(pem), use_system_ca=True)
    assert result["NODE_EXTRA_CA_CERTS"] == str(pem)
    assert result["NODE_OPTIONS"] == "--use-system-ca"


def test_tls_env_vars_all_three(tmp_path):
    pem = tmp_path / "ca.pem"
    pem.write_text("cert")
    result = bv._tls_env_vars(
        ca_cert=str(pem), insecure_tls=True, use_system_ca=True
    )
    assert result["NODE_EXTRA_CA_CERTS"] == str(pem)
    assert result["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"
    assert "--use-system-ca" in result["NODE_OPTIONS"]


def test_tls_env_vars_use_system_ca_appends_to_existing_node_options():
    """use_system_ca should append to a pre-existing NODE_OPTIONS value."""
    # Simulate a caller that already has NODE_OPTIONS set; _tls_env_vars itself
    # starts from scratch, so two calls with different flags should compose.
    r1 = bv._tls_env_vars(use_system_ca=True)
    # The resulting value should not have leading/trailing spaces.
    assert r1["NODE_OPTIONS"] == "--use-system-ca"
    assert not r1["NODE_OPTIONS"].startswith(" ")


# ---------------------------------------------------------------------------
# TLS env vars pass-through via fetch_vault_secrets
# ---------------------------------------------------------------------------


def test_fetch_passes_ca_cert_to_run_bw(monkeypatch, tmp_path):
    """NODE_EXTRA_CA_CERTS must appear in every _run_bw call when ca_cert is set."""
    pem = tmp_path / "ca.pem"
    pem.write_text("cert")
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner()
    observed_envs: list[dict] = []

    def capturing_run_bw(bw_bin, args, **kw):
        observed_envs.append(dict(kw.get("env_extra") or {}))
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", capturing_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", runner)

    bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        use_cache=False,
        ca_cert=str(pem),
    )
    assert observed_envs, "expected _run_bw to be called"
    for env in observed_envs:
        assert env.get("NODE_EXTRA_CA_CERTS") == str(pem), (
            f"expected NODE_EXTRA_CA_CERTS in {env}"
        )


def test_fetch_passes_use_system_ca_to_run_bw(monkeypatch, tmp_path):
    """NODE_OPTIONS=--use-system-ca must be set when use_system_ca=True."""
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner()
    observed_envs: list[dict] = []

    def capturing_run_bw(bw_bin, args, **kw):
        observed_envs.append(dict(kw.get("env_extra") or {}))
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", capturing_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", runner)

    bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        use_cache=False,
        use_system_ca=True,
    )
    assert observed_envs
    for env in observed_envs:
        assert "--use-system-ca" in env.get("NODE_OPTIONS", ""), (
            f"expected --use-system-ca in NODE_OPTIONS in {env}"
        )


def test_fetch_no_tls_env_when_defaults(monkeypatch, tmp_path):
    """No TLS env vars should be injected when all TLS params are default."""
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner()
    observed_envs: list[dict] = []

    def capturing_run_bw(bw_bin, args, **kw):
        observed_envs.append(dict(kw.get("env_extra") or {}))
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", capturing_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", runner)

    bv.fetch_vault_secrets(
        email="user@example.com",
        binary=fake_bin,
        use_cache=False,
    )
    for env in observed_envs:
        assert "NODE_EXTRA_CA_CERTS" not in env
        assert "NODE_OPTIONS" not in env
        assert "NODE_TLS_REJECT_UNAUTHORIZED" not in env


# ---------------------------------------------------------------------------
# apply_vault_secrets — TLS param pass-through
# ---------------------------------------------------------------------------


def test_apply_passes_use_system_ca(monkeypatch, tmp_path):
    """use_system_ca=True must reach _run_bw as NODE_OPTIONS."""
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner()
    observed_envs: list[dict] = []

    def capturing_run_bw(bw_bin, args, **kw):
        observed_envs.append(dict(kw.get("env_extra") or {}))
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "find_bw", lambda **kw: fake_bin)
    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", capturing_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", runner)

    result = bv.apply_vault_secrets(
        enabled=True,
        email="user@example.com",
        auto_install=False,
        use_system_ca=True,
    )
    assert result.ok
    assert observed_envs
    assert any(
        "--use-system-ca" in e.get("NODE_OPTIONS", "") for e in observed_envs
    ), f"expected --use-system-ca in at least one call, got: {observed_envs}"


def test_apply_passes_ca_cert(monkeypatch, tmp_path):
    """ca_cert path must reach _run_bw as NODE_EXTRA_CA_CERTS."""
    pem = tmp_path / "ca.pem"
    pem.write_text("cert")
    fake_bin = tmp_path / "bw"
    fake_bin.write_text("")
    runner = FakeBwRunner()
    observed_envs: list[dict] = []

    def capturing_run_bw(bw_bin, args, **kw):
        observed_envs.append(dict(kw.get("env_extra") or {}))
        return runner([str(bw_bin)] + args)

    monkeypatch.setattr(bv, "find_bw", lambda **kw: fake_bin)
    monkeypatch.setattr(bv, "_read_master_password", lambda *a, **kw: "pw")
    monkeypatch.setattr(bv, "_run_bw", capturing_run_bw)
    monkeypatch.setattr(bv.subprocess, "run", runner)

    result = bv.apply_vault_secrets(
        enabled=True,
        email="user@example.com",
        auto_install=False,
        ca_cert=str(pem),
    )
    assert result.ok
    assert any(
        e.get("NODE_EXTRA_CA_CERTS") == str(pem) for e in observed_envs
    ), f"expected NODE_EXTRA_CA_CERTS in at least one call, got: {observed_envs}"

