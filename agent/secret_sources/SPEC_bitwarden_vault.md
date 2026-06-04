# Specification: Bitwarden Vault Secret Source

> Module: `agent/secret_sources/bitwarden_vault.py`
> CLI: `hermes secrets bitwarden-vault ...`
> Config key: `secrets.bitwarden_vault`

## Overview

A secret source that pulls credentials from **Bitwarden Vault** (the password manager product) using the `bw` CLI, complementing the existing Bitwarden **Secrets Manager** (`bws`) integration. Each secret is a separate Vault item in a designated folder, with the item's **name** mapping directly to the environment variable name.

---

## Architecture

### Relationship to Existing `bws` Integration

| Aspect | Existing (`bws` / Secrets Manager) | New (`bw` / Vault) |
|--------|-------------------------------------|---------------------|
| CLI binary | `bws` | `bw` |
| Auth | Machine access token | Master password → session token |
| Secret scope | Project ID | Folder name (default: `hermes`) |
| Item model | Flat key/value | Vault items (Login or Secure Note) |
| Module | `bitwarden.py` | `bitwarden_vault.py` |
| Config key | `secrets.bitwarden` | `secrets.bitwarden_vault` |
| CLI subcommand | `hermes secrets bitwarden ...` | `hermes secrets bitwarden-vault ...` |

---

## Secret Organization

- Secrets live in a Bitwarden Vault **folder** (default name: `hermes`).
- Each item in the folder represents one secret:
  - **Item name** = environment variable name (e.g. `OPENAI_API_KEY`)
  - **Item value** = depends on item type:
    - **Login** → `login.password` field
    - **Secure Note** → `notes` field
  - Detection is automatic based on item type.
- Items outside the configured folder are never touched.

---

## Authentication & Session Management

### Bootstrap Credential: Master Password

The master password is the single bootstrap secret needed to unlock the vault.

**Storage strategy (layered):**

1. **Primary: OS keychain** via the `keyring` Python package
   - Service name: `hermes-bitwarden-vault`
   - Username: the Bitwarden email address
   - Cross-platform: GNOME Keyring / KWallet on Linux, Keychain on macOS, Windows Credential Locker
2. **Fallback: Password file** at `~/.hermes/.bw_master_password`
   - Mode `0600`, owned by the user
   - Used on headless Linux servers where no keyring daemon is available
   - Created by the setup wizard when keyring is unavailable

### Session Token Lifecycle

1. `bw unlock --passwordfile <path>` (or pipe from keyring) → produces a session token
2. Session token is stored **in-process** (never persisted to disk)
3. On expiry (detected by `bw` returning auth errors), re-unlock automatically
4. The `--passwordfile` approach avoids passing the master password as a CLI argument (visible in `ps`)

### Server Configuration

| Config key | Purpose | Default |
|-----------|---------|---------|
| `server_url` | Base URL (`bw config server <url>`) | `https://vault.bitwarden.com` |
| `identity_url` | Identity endpoint (optional override) | _(derived from base)_ |
| `api_url` | API endpoint (optional override) | _(derived from base)_ |

Self-hosted users set `server_url`; the optional `identity_url` / `api_url` fields are for non-standard deployments only.

### Two-Factor Authentication

- 2FA is handled **during the setup wizard only** (interactive `bw login` with TOTP prompt)
- After initial login, the device is remembered; subsequent `bw unlock` does not require 2FA
- The setup wizard guides the user through `bw login` if they aren't already logged in

---

## `bw` CLI Binary Management

### Auto-Installation

- Binary installed to `~/.hermes/bin/bw`
- Downloaded from official GitHub Releases: `https://github.com/bitwarden/clients/releases`
- Pinned version (e.g. `2024.12.0`) — never auto-resolves "latest"
- SHA-256 checksum verification against the release's published checksums
- Platform detection: Linux (x64/arm64), macOS (universal), Windows (x64)

### Resolution Order

1. `<hermes_home>/bin/bw` (managed copy — preferred)
2. `shutil.which("bw")` (system PATH)
3. Auto-install if `auto_install: true`

---

## Caching Strategy

**Dual-layer cache (same pattern as `bws` integration):**

1. **In-process dict** — keyed on `(email_hash, folder_name, server_url)`
   - Avoids redundant fetches within a single process
2. **Disk cache** at `~/.hermes/cache/bw_vault_cache.json`
   - Mode `0600`, atomic write via temp file + rename
   - Stores secret values + `fetched_at` timestamp
   - Shared across processes (gateway forking agents, cron, etc.)
3. **TTL** — configurable via `cache_ttl_seconds` (default: 86400s / 1 day)

---

## config.yaml Schema

```yaml
secrets:
  bitwarden_vault:
    enabled: false
    email: ""                    # Bitwarden account email
    folder_name: "hermes"       # Vault folder containing secrets
    cache_ttl_seconds: 86400       # 1 day
    override_existing: false    # If true, overwrite env vars already set
    auto_install: true          # Auto-download bw CLI if missing
    server_url: ""              # Self-hosted base URL (empty = cloud default)
    identity_url: ""            # Optional: custom identity endpoint
    api_url: ""                 # Optional: custom API endpoint
    org_id: ""                  # Organization ID (empty = personal vault)
    password_storage: "auto"    # "keyring", "file", or "auto" (try keyring, fall back to file)
```

---

## CLI Subcommands: `hermes secrets bitwarden-vault ...`

### `setup` — Interactive wizard

1. Check/install `bw` binary
2. Prompt for email + server URL (if self-hosted)
3. Run `bw login` (handles 2FA interactively)
4. Prompt for master password → store in keyring (or file fallback)
5. Verify unlock works (`bw unlock --passwordfile`)
6. List folders → let user pick or create `hermes` folder
7. Test fetch: list items in folder, show what would be applied
8. Write config to `config.yaml`

### `status` — Show current state

- Config summary (enabled, email, folder, server)
- Binary version + location
- Keyring/password-file status
- Session token validity
- Last cache fetch time + item count

### `sync` — Fetch secrets now

- `--apply`: actually export into env (default: dry-run showing what would change)
- Shows applied / skipped / warnings

### `disable` — Turn off

- Sets `secrets.bitwarden_vault.enabled: false` in config

### `install` — Just download the binary

- No auth required; useful for pre-provisioning

---

## Failure Behavior

- **Never blocks Hermes startup**
- Missing binary, no network, expired session, locked vault → one-line warning, continue
- `FetchResult` with `error` field set on fatal conditions
- All exceptions caught at the `_apply_external_secret_sources` boundary

---

## `bw` CLI Commands Used

| Operation | Command |
|-----------|---------|
| Login | `bw login <email> --passwordfile <path>` |
| Unlock | `bw unlock --passwordfile <path>` → captures session key |
| Sync vault | `bw sync --session <token>` (with timeout guard) |
| List items in folder | `bw list items --folderid <id> --session <token>` |
| List folders | `bw list folders --session <token>` |
| Check status | `bw status` |
| Set server | `bw config server <url>` |

All commands run with `--nointeraction` and `--raw` / `--output json` where applicable. Environment: `BW_SESSION=<token>`, `NO_COLOR=1`.

---

## Data Flow

```
Hermes startup
    │
    ▼
load_hermes_dotenv()
    │
    ▼
_apply_external_secret_sources(home_path)
    │
    ├─ [existing] Bitwarden Secrets Manager (bws)
    │
    └─ [NEW] Bitwarden Vault (bw)
         │
         ├─ Check in-process cache → hit? return
         ├─ Check disk cache → hit & fresh? return
         │
         ├─ Read master password (keyring → file fallback)
         ├─ `bw unlock --passwordfile` → session token
         ├─ `bw sync --session` (with timeout guard)
         ├─ `bw list folders --session` → find folder ID
         ├─ `bw list items --folderid <id> --session` → JSON
         │
         ├─ For each item:
         │     name → env var name
         │     Login type → login.password = value
         │     Secure Note type → notes = value
         │
         ├─ Apply to os.environ (respect override_existing)
         ├─ Update in-process + disk cache
         └─ Return FetchResult
```

---

## Module Public API

```python
# agent/secret_sources/bitwarden_vault.py

@dataclass
class FetchResult:
    secrets: Dict[str, str]
    applied: List[str]
    skipped: List[str]
    warnings: List[str]
    error: Optional[str]
    binary_path: Optional[Path]

def find_bw(*, install_if_missing: bool = False) -> Optional[Path]
def install_bw(*, force: bool = False) -> Path
def fetch_vault_secrets(
    *,
    email: str,
    folder_name: str = "hermes",
    binary: Optional[Path] = None,
    cache_ttl_seconds: float = 86400,
    use_cache: bool = True,
    server_url: str = "",
    home_path: Optional[Path] = None,
    password_storage: str = "auto",
) -> Tuple[Dict[str, str], List[str]]

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
) -> FetchResult
```

---

## Dependencies

| Dependency | Purpose | Install strategy |
|-----------|---------|-----------------|
| `keyring` | Cross-platform credential storage | Already in hermes deps (or add to `pyproject.toml`) |
| `bw` CLI | Bitwarden Vault operations | Auto-installed to `~/.hermes/bin/bw` |

---

## Security Considerations

- Master password **never** passed as a CLI argument (visible in `/proc/<pid>/cmdline`)
- Password file is `0600` and contains only the password (no other data)
- Session tokens are ephemeral (in-process only, never written to disk)
- Disk cache stores secret **values** (same security posture as `.env` — acceptable)
- `bw` binary verified via SHA-256 checksum before execution
- Input validation: item names must match `[A-Za-z_][A-Za-z0-9_]*` to be valid env vars

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `agent/secret_sources/bitwarden_vault.py` | Create — main integration module |
| `agent/secret_sources/__init__.py` | Update — add docstring reference |
| `hermes_cli/secrets_cli_vault.py` | Create — CLI handlers for `bitwarden-vault` subcommands |
| `hermes_cli/env_loader.py` | Modify — add `bitwarden_vault` block in `_apply_external_secret_sources` |
| `config.yaml` | Add `secrets.bitwarden_vault` section |
| `pyproject.toml` | Add `keyring` dependency if not present |

---

## Design Decisions (Resolved)

- **`bw sync` before list**: Yes, always called with a timeout guard to ensure fresh data.
- **Organization vaults**: Supported via `org_id` config key. When set, `bw list items` is scoped to the organization. Empty = personal vault.
- **Folder auto-creation**: Setup wizard offers to create the `hermes` folder if it doesn't exist.

---

## Future Work

- Item creation helper (`hermes secrets bitwarden-vault add OPENAI_API_KEY`)
