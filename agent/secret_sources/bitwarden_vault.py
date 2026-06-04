"""Bitwarden Vault (`bw` CLI) integration.

Hermes pulls API keys from a Bitwarden Vault folder at process startup.
Each Vault item in the designated folder maps to one environment variable:
  - Item name = env var name (e.g. ``OPENAI_API_KEY``)
  - Login type → ``login.password`` field = value
  - Secure Note type → ``notes`` field = value

This complements the existing Bitwarden Secrets Manager (``bws``) integration.

Design summary
--------------

* The ``bw`` binary is auto-installed into ``<hermes_home>/bin/bw`` on
  first use.  Hermes pins one version and downloads the matching asset
  from the official GitHub Releases page, verifying the SHA-256 against
  the release's published checksum file.
* The master password is the single bootstrap secret.  It's stored in
  the OS keychain (via ``keyring``) or a file fallback at
  ``~/.hermes/.bw_master_password`` (mode 0600).
* Session tokens are held in-process only — never persisted to disk.
* Failures NEVER block Hermes startup.  Missing binary, no network,
  expired session, etc. all emit a one-line warning and continue.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

_BW_VERSION = "2024.12.0"

_BW_RELEASE_BASE = (
    f"https://github.com/bitwarden/clients/releases/download/cli-v{_BW_VERSION}"
)
_BW_CHECKSUM_NAME = f"bw-sha256-checksums-{_BW_VERSION}.txt"

_BW_DOWNLOAD_TIMEOUT = 120
_BW_RUN_TIMEOUT = 30
_BW_SYNC_TIMEOUT = 60

# Valid env var name pattern
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# In-process cache
_CacheKey = Tuple[str, str, str]  # (email_hash, folder_name, server_url)
_CACHE: Dict[_CacheKey, "_CachedFetch"] = {}

_DISK_CACHE_BASENAME = "bw_vault_cache.json"

# Keyring service name
_KEYRING_SERVICE = "hermes-bitwarden-vault"

# Password file location (relative to hermes home)
_PASSWORD_FILE_NAME = ".bw_master_password"


def _disk_cache_path(home_path: Optional[Path] = None) -> Path:
    if home_path is None:
        home_path = Path(os.getenv("HERMES_HOME", Path.home() / ".hermes"))
    return home_path / "cache" / _DISK_CACHE_BASENAME


def _cache_key_str(cache_key: _CacheKey) -> str:
    email_hash, folder_name, server_url = cache_key
    return f"{email_hash}|{folder_name}|{server_url}"


def _read_disk_cache(
    cache_key: _CacheKey, ttl_seconds: float, home_path: Optional[Path] = None
) -> Optional["_CachedFetch"]:
    if ttl_seconds <= 0:
        return None
    path = _disk_cache_path(home_path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("key") != _cache_key_str(cache_key):
        return None
    secrets = payload.get("secrets")
    fetched_at = payload.get("fetched_at")
    if not isinstance(secrets, dict) or not isinstance(fetched_at, (int, float)):
        return None
    typed_secrets: Dict[str, str] = {
        k: v for k, v in secrets.items() if isinstance(k, str) and isinstance(v, str)
    }
    entry = _CachedFetch(secrets=typed_secrets, fetched_at=float(fetched_at))
    if not entry.is_fresh(ttl_seconds):
        return None
    return entry


def _write_disk_cache(
    cache_key: _CacheKey, entry: "_CachedFetch", home_path: Optional[Path] = None
) -> None:
    path = _disk_cache_path(home_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "key": _cache_key_str(cache_key),
            "secrets": entry.secrets,
            "fetched_at": entry.fetched_at,
        }
        fd, tmp = tempfile.mkstemp(
            prefix=".bw_vault_cache_", suffix=".tmp", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass


@dataclass
class _CachedFetch:
    secrets: Dict[str, str]
    fetched_at: float

    def is_fresh(self, ttl_seconds: float) -> bool:
        if ttl_seconds <= 0:
            return False
        return (time.time() - self.fetched_at) < ttl_seconds


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FetchResult:
    """Outcome of a Bitwarden Vault pull."""

    secrets: Dict[str, str] = field(default_factory=dict)
    applied: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None
    binary_path: Optional[Path] = None

    @property
    def ok(self) -> bool:
        return self.error is None


# ---------------------------------------------------------------------------
# Binary discovery + lazy install
# ---------------------------------------------------------------------------


def _hermes_bin_dir() -> Path:
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "bin"


def find_bw(*, install_if_missing: bool = False) -> Optional[Path]:
    """Return a path to a usable ``bw`` binary, or None.

    Resolution order:
      1. ``<hermes_home>/bin/bw``  (our managed copy — preferred)
      2. ``shutil.which("bw")``    (system PATH)
      3. Auto-install if requested
    """
    managed = _hermes_bin_dir() / _platform_binary_name()
    if managed.exists() and os.access(managed, os.X_OK):
        return managed

    system = shutil.which("bw")
    if system:
        return Path(system)

    if install_if_missing:
        try:
            return install_bw()
        except Exception as exc:  # noqa: BLE001
            logger.warning("bw auto-install failed: %s", exc)
            return None
    return None


def _platform_binary_name() -> str:
    return "bw.exe" if platform.system() == "Windows" else "bw"


def _platform_asset_name() -> str:
    """Map platform → the upstream asset filename."""
    system = platform.system()

    if system == "Darwin":
        return f"bw-macos-{_BW_VERSION}.zip"

    if system == "Windows":
        return f"bw-windows-{_BW_VERSION}.zip"

    if system == "Linux":
        return f"bw-linux-{_BW_VERSION}.zip"

    raise RuntimeError(f"Unsupported platform for bw auto-install: {system}")


def install_bw(*, force: bool = False) -> Path:
    """Download, verify, and install the pinned ``bw`` binary."""
    bin_dir = _hermes_bin_dir()
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir / _platform_binary_name()

    if target.exists() and not force:
        return target

    asset_name = _platform_asset_name()
    asset_url = f"{_BW_RELEASE_BASE}/{asset_name}"
    checksum_url = f"{_BW_RELEASE_BASE}/{_BW_CHECKSUM_NAME}"

    with tempfile.TemporaryDirectory(prefix="hermes-bw-") as tmpdir:
        tmp = Path(tmpdir)
        zip_path = tmp / asset_name
        checksum_path = tmp / _BW_CHECKSUM_NAME

        logger.info("Downloading %s", asset_url)
        _http_download(asset_url, zip_path)
        _http_download(checksum_url, checksum_path)

        expected = _expected_sha256(checksum_path, asset_name)
        actual = _sha256_file(zip_path)
        if expected.lower() != actual.lower():
            raise RuntimeError(
                f"Checksum mismatch for {asset_name}: expected {expected}, got {actual}"
            )

        with zipfile.ZipFile(zip_path) as zf:
            member = _pick_zip_member(zf, _platform_binary_name())
            zf.extract(member, tmp)
            extracted = tmp / member

        fd, staged = tempfile.mkstemp(dir=str(bin_dir), prefix=".bw_")
        os.close(fd)
        shutil.copy2(extracted, staged)
        os.chmod(
            staged,
            stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IXUSR
            | stat.S_IRGRP
            | stat.S_IXGRP
            | stat.S_IROTH
            | stat.S_IXOTH,
        )
        os.replace(staged, target)

    logger.info("Installed bw %s at %s", _BW_VERSION, target)
    return target


def _http_download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "hermes-agent"})
    try:
        with urllib.request.urlopen(req, timeout=_BW_DOWNLOAD_TIMEOUT) as resp:  # noqa: S310
            with open(dest, "wb") as f:
                shutil.copyfileobj(resp, f)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to download {url}: {exc}") from exc


def _expected_sha256(checksum_file: Path, asset_name: str) -> str:
    text = checksum_file.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[-1] == asset_name:
            return parts[0]
    raise RuntimeError(f"No checksum entry for {asset_name} in {checksum_file.name}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _pick_zip_member(zf: zipfile.ZipFile, binary_name: str) -> str:
    candidates = [n for n in zf.namelist() if n.split("/")[-1] == binary_name]
    if not candidates:
        raise RuntimeError(
            f"Could not find {binary_name} inside downloaded archive "
            f"(members: {zf.namelist()[:5]}...)"
        )
    candidates.sort(key=len)
    return candidates[0]


# ---------------------------------------------------------------------------
# Master password management
# ---------------------------------------------------------------------------


def _password_file_path(home_path: Optional[Path] = None) -> Path:
    if home_path is None:
        home_path = Path(os.getenv("HERMES_HOME", Path.home() / ".hermes"))
    return home_path / _PASSWORD_FILE_NAME


def _read_master_password(
    email: str,
    password_storage: str = "auto",
    home_path: Optional[Path] = None,
) -> Optional[str]:
    """Read master password from keyring or file fallback.

    Returns None if unavailable.
    """
    if password_storage in ("keyring", "auto"):
        pw = _read_from_keyring(email)
        if pw:
            return pw
        if password_storage == "keyring":
            return None

    # File fallback
    if password_storage in ("file", "auto"):
        pw = _read_from_file(home_path)
        if pw:
            return pw

    return None


def _read_from_keyring(email: str) -> Optional[str]:
    """Try to read password from OS keychain."""
    try:
        import keyring as kr

        pw = kr.get_password(_KEYRING_SERVICE, email)
        return pw if pw else None
    except Exception:  # noqa: BLE001
        return None


def _write_to_keyring(email: str, password: str) -> bool:
    """Store password in OS keychain. Returns True on success."""
    try:
        import keyring as kr

        kr.set_password(_KEYRING_SERVICE, email, password)
        return True
    except Exception:  # noqa: BLE001
        return False


def _read_from_file(home_path: Optional[Path] = None) -> Optional[str]:
    """Read password from the file fallback."""
    path = _password_file_path(home_path)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _write_to_file(password: str, home_path: Optional[Path] = None) -> Path:
    """Write password to file with mode 0600."""
    path = _password_file_path(home_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".bw_pw_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(password)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def store_master_password(
    email: str,
    password: str,
    password_storage: str = "auto",
    home_path: Optional[Path] = None,
) -> str:
    """Store master password. Returns the storage method used ("keyring" or "file")."""
    if password_storage in ("keyring", "auto"):
        if _write_to_keyring(email, password):
            return "keyring"
        if password_storage == "keyring":
            raise RuntimeError(
                "Failed to store password in keyring. "
                "Ensure a keyring backend is available."
            )

    # File fallback
    _write_to_file(password, home_path)
    return "file"


# ---------------------------------------------------------------------------
# bw CLI helpers
# ---------------------------------------------------------------------------


def _run_bw(
    bw: Path,
    args: List[str],
    *,
    session: str = "",
    env_extra: Optional[Dict[str, str]] = None,
    timeout: int = _BW_RUN_TIMEOUT,
    input_data: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a bw command with standard options."""
    cmd = [str(bw)] + args + ["--nointeraction", "--raw"]
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if session:
        env["BW_SESSION"] = session
    if env_extra:
        env.update(env_extra)

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"bw timed out after {timeout}s: {' '.join(args[:2])}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"failed to invoke bw: {exc}") from exc

    return proc


def _get_session_token(
    bw: Path,
    email: str,
    password_storage: str = "auto",
    home_path: Optional[Path] = None,
    server_url: str = "",
    identity_url: str = "",
    api_url: str = "",
    ca_cert: str = "",
    insecure_tls: bool = False,
    use_system_ca: bool = False,
) -> str:
    """Unlock the vault and return a session token.

    Uses a temporary password file to avoid passing the master password
    as a CLI argument (visible in /proc/<pid>/cmdline).
    """
    master_password = _read_master_password(email, password_storage, home_path)
    if not master_password:
        raise RuntimeError(
            "Master password not found. Run `hermes secrets bitwarden-vault setup`."
        )

    tls_env = _tls_env_vars(ca_cert, insecure_tls, use_system_ca)

    # Configure server if needed
    if server_url:
        _configure_server(bw, server_url, identity_url, api_url, tls_env)

    # Check login status first
    status = _check_status(bw, tls_env)
    if status.get("status") == "unauthenticated":
        raise RuntimeError(
            "Not logged in to Bitwarden. Run `hermes secrets bitwarden-vault setup`."
        )

    # Write password to a temp file for --passwordfile
    tmp_dir = Path(tempfile.gettempdir())
    fd, pw_file = tempfile.mkstemp(dir=str(tmp_dir), prefix=".hermes_bw_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(master_password)
        os.chmod(pw_file, 0o600)

        proc = _run_bw(bw, ["unlock", "--passwordfile", pw_file], env_extra=tls_env)
    finally:
        try:
            os.unlink(pw_file)
        except OSError:
            pass

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"bw unlock failed: {err[:200]}")

    # --raw mode returns just the session key
    session = proc.stdout.strip()
    if not session:
        raise RuntimeError("bw unlock returned empty session token")

    return session


def _configure_server(
    bw: Path,
    server_url: str,
    identity_url: str = "",
    api_url: str = "",
    tls_env: Optional[Dict[str, str]] = None,
) -> None:
    """Set the bw server configuration for self-hosted instances."""
    args = ["config", "server", server_url]
    proc = _run_bw(bw, args, env_extra=tls_env or {})
    if proc.returncode != 0:
        logger.warning("bw config server failed: %s", proc.stderr.strip()[:100])


def _check_status(bw: Path, tls_env: Optional[Dict[str, str]] = None) -> dict:
    """Run bw status and return the parsed JSON."""
    # bw status doesn't use --raw well, use --output json equivalent
    cmd = [str(bw), "status", "--nointeraction"]
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if tls_env:
        env.update(tls_env)
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=_BW_RUN_TIMEOUT
        )
    except (subprocess.TimeoutExpired, OSError):
        return {}

    try:
        return json.loads(proc.stdout.strip())
    except (json.JSONDecodeError, ValueError):
        return {}


def _sync_vault(
    bw: Path, session: str, tls_env: Optional[Dict[str, str]] = None
) -> None:
    """Sync the local vault cache with the server."""
    proc = _run_bw(
        bw, ["sync"], session=session, timeout=_BW_SYNC_TIMEOUT, env_extra=tls_env or {}
    )
    if proc.returncode != 0:
        logger.warning("bw sync failed (non-fatal): %s", proc.stderr.strip()[:100])


def _list_folders(
    bw: Path, session: str, tls_env: Optional[Dict[str, str]] = None
) -> List[dict]:
    """List all folders in the vault."""
    cmd = [str(bw), "list", "folders", "--nointeraction", "--session", session]
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if tls_env:
        env.update(tls_env)

    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=_BW_RUN_TIMEOUT
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise RuntimeError(f"bw list folders failed: {exc}") from exc

    if proc.returncode != 0:
        raise RuntimeError(f"bw list folders failed: {proc.stderr.strip()[:200]}")

    try:
        folders = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"bw list folders returned non-JSON: {exc}") from exc

    return folders if isinstance(folders, list) else []


def _find_folder_id(
    bw: Path,
    session: str,
    folder_name: str,
    tls_env: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Find the folder ID for the given folder name."""
    folders = _list_folders(bw, session, tls_env)
    for folder in folders:
        if isinstance(folder, dict) and folder.get("name") == folder_name:
            return folder.get("id")
    return None


def _list_items_in_folder(
    bw: Path,
    session: str,
    folder_id: str,
    org_id: str = "",
    tls_env: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """List items in a specific folder."""
    cmd = [
        str(bw),
        "list",
        "items",
        "--folderid",
        folder_id,
        "--nointeraction",
        "--session",
        session,
    ]
    if org_id:
        cmd.extend(["--organizationid", org_id])

    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if tls_env:
        env.update(tls_env)

    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=_BW_RUN_TIMEOUT
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise RuntimeError(f"bw list items failed: {exc}") from exc

    if proc.returncode != 0:
        raise RuntimeError(f"bw list items failed: {proc.stderr.strip()[:200]}")

    try:
        items = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"bw list items returned non-JSON: {exc}") from exc

    return items if isinstance(items, list) else []


def _extract_secret_value(item: dict) -> Optional[str]:
    """Extract the secret value from a vault item based on its type.

    Type 1 = Login → login.password
    Type 2 = Secure Note → notes
    """
    item_type = item.get("type")

    if item_type == 1:  # Login
        login = item.get("login")
        if isinstance(login, dict):
            return login.get("password")
    elif item_type == 2:  # Secure Note
        return item.get("notes")

    return None


def _is_valid_env_name(name: str) -> bool:
    """Check if a string is a valid environment variable name."""
    return bool(_ENV_NAME_RE.match(name))


def _tls_env_vars(
    ca_cert: str = "",
    insecure_tls: bool = False,
    use_system_ca: bool = False,
) -> Dict[str, str]:
    """Return env var additions to configure TLS for the bw (Node.js) CLI.

    ``ca_cert`` — path to a PEM CA certificate (for self-signed / internal CAs).
    ``insecure_tls`` — disable TLS verification entirely (not recommended).
    ``use_system_ca`` — pass ``--use-system-ca`` to Node (Node 24+); trusts
        any certificate already installed in the OS trust store.
    """
    extra: Dict[str, str] = {}
    if ca_cert:
        extra["NODE_EXTRA_CA_CERTS"] = ca_cert
    if insecure_tls:
        extra["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
    if use_system_ca:
        existing = extra.get("NODE_OPTIONS", "")
        extra["NODE_OPTIONS"] = (
            (existing + " --use-system-ca").strip()
        )
    return extra


def _email_fingerprint(email: str) -> str:
    """SHA-256 prefix of email for cache key — never logged."""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Secret fetch + apply
# ---------------------------------------------------------------------------


def fetch_vault_secrets(
    *,
    email: str,
    folder_name: str = "hermes",
    binary: Optional[Path] = None,
    cache_ttl_seconds: float = 86400,
    use_cache: bool = True,
    server_url: str = "",
    identity_url: str = "",
    api_url: str = "",
    org_id: str = "",
    home_path: Optional[Path] = None,
    password_storage: str = "auto",
    ca_cert: str = "",
    insecure_tls: bool = False,
    use_system_ca: bool = False,
) -> Tuple[Dict[str, str], List[str]]:
    """Pull secrets from the Bitwarden Vault folder.

    Returns ``(secrets_dict, warnings_list)``.
    """
    if not email:
        raise RuntimeError("Bitwarden Vault email is empty")

    cache_key = (_email_fingerprint(email), folder_name, server_url or "")
    if use_cache:
        cached = _CACHE.get(cache_key)
        if cached and cached.is_fresh(cache_ttl_seconds):
            return cached.secrets, []
        disk_cached = _read_disk_cache(cache_key, cache_ttl_seconds, home_path)
        if disk_cached is not None:
            _CACHE[cache_key] = disk_cached
            return disk_cached.secrets, []

    bw = binary or find_bw(install_if_missing=True)
    if bw is None:
        raise RuntimeError(
            "bw binary not available — auto-install failed and `bw` is "
            "not on PATH. Run `hermes secrets bitwarden-vault setup`."
        )

    # Get session token
    session = _get_session_token(
        bw, email, password_storage, home_path, server_url, identity_url, api_url,
        ca_cert, insecure_tls, use_system_ca,
    )

    # Sync vault
    tls_env = _tls_env_vars(ca_cert, insecure_tls, use_system_ca)
    _sync_vault(bw, session, tls_env)

    # Find the folder
    folder_id = _find_folder_id(bw, session, folder_name, tls_env)
    if folder_id is None:
        raise RuntimeError(
            f"Folder '{folder_name}' not found in Bitwarden Vault. "
            f"Run `hermes secrets bitwarden-vault setup` to create it."
        )

    # List items
    items = _list_items_in_folder(bw, session, folder_id, org_id, tls_env)

    secrets: Dict[str, str] = {}
    warnings: List[str] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        if not _is_valid_env_name(name):
            warnings.append(f"Skipping item {name!r}: not a valid env-var name")
            continue
        value = _extract_secret_value(item)
        if value is None:
            warnings.append(
                f"Skipping item {name!r}: unsupported item type or empty value"
            )
            continue
        secrets[name] = value

    # Update caches
    entry = _CachedFetch(secrets=secrets, fetched_at=time.time())
    _CACHE[cache_key] = entry
    if use_cache:
        _write_disk_cache(cache_key, entry, home_path)

    return secrets, warnings


def apply_vault_secrets(
    *,
    enabled: bool,
    email: str = "",
    folder_name: str = "hermes",
    override_existing: bool = False,
    cache_ttl_seconds: float = 86400,
    auto_install: bool = True,
    server_url: str = "",
    identity_url: str = "",
    api_url: str = "",
    org_id: str = "",
    home_path: Optional[Path] = None,
    password_storage: str = "auto",
    ca_cert: str = "",
    insecure_tls: bool = False,
    use_system_ca: bool = False,
) -> FetchResult:
    """Pull secrets from Bitwarden Vault and set them on ``os.environ``.

    This is called from ``_apply_external_secret_sources()`` in
    env_loader.py. Intentionally defensive — any failure returns a
    :class:`FetchResult` with ``error`` set; it never raises.
    """
    result = FetchResult()

    if not enabled:
        return result

    if not email:
        result.error = (
            "secrets.bitwarden_vault.enabled is true but email is not set. "
            "Run `hermes secrets bitwarden-vault setup`."
        )
        return result

    binary = find_bw(install_if_missing=auto_install)
    result.binary_path = binary
    if binary is None:
        result.error = (
            "bw binary not available and auto-install is disabled. "
            "Run `hermes secrets bitwarden-vault setup` to install."
        )
        return result

    try:
        secrets, warnings = fetch_vault_secrets(
            email=email,
            folder_name=folder_name,
            binary=binary,
            cache_ttl_seconds=cache_ttl_seconds,
            server_url=server_url,
            identity_url=identity_url,
            api_url=api_url,
            org_id=org_id,
            home_path=home_path,
            password_storage=password_storage,
            ca_cert=ca_cert,
            insecure_tls=insecure_tls,
            use_system_ca=use_system_ca,
        )
    except RuntimeError as exc:
        result.error = str(exc)
        return result

    result.secrets = secrets
    result.warnings.extend(warnings)

    for key, value in secrets.items():
        if not override_existing and os.environ.get(key):
            result.skipped.append(key)
            continue
        os.environ[key] = value
        result.applied.append(key)

    return result


# ---------------------------------------------------------------------------
# Test hook
# ---------------------------------------------------------------------------


def _reset_cache_for_tests(home_path: Optional[Path] = None) -> None:
    """Clear in-process AND disk caches."""
    _CACHE.clear()
    try:
        _disk_cache_path(home_path).unlink()
    except (FileNotFoundError, OSError):
        pass
