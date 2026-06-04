"""CLI handlers for ``hermes secrets bitwarden-vault ...``.

Subcommands:
    setup    — interactive wizard: install bw, prompt for email + password, test fetch
    status   — show current config + binary version + last fetch outcome
    sync     — run a fetch right now and show what would be applied (dry-run friendly)
    disable  — flip ``secrets.bitwarden_vault.enabled`` to False
    install  — just download the bw binary (no token / project required)
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent.secret_sources import bitwarden_vault as bwv
from hermes_cli.config import load_config, save_config
from hermes_cli.secret_prompt import masked_secret_prompt


# ---------------------------------------------------------------------------
# Argparse wiring — called from hermes_cli.main
# ---------------------------------------------------------------------------


def register_cli(parent_parser: argparse.ArgumentParser) -> None:
    """Attach the ``bitwarden-vault`` subcommand tree to a parent parser."""
    sub = parent_parser.add_subparsers(dest="secrets_bwv_command")

    setup = sub.add_parser(
        "setup",
        help="Interactive wizard: install bw, store master password, pick folder",
    )
    setup.add_argument(
        "--email",
        help="Bitwarden account email (skips interactive prompt)",
    )
    setup.add_argument(
        "--folder",
        help="Vault folder name to use (default: hermes)",
    )
    setup.add_argument(
        "--server-url",
        help="Self-hosted Bitwarden server URL (empty = cloud default)",
    )
    setup.add_argument(
        "--ca-cert",
        help="Path to a PEM CA certificate for self-signed / internal TLS (e.g. for https://bitwarden.mycompany.local)",
    )
    setup.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (not recommended; use --ca-cert instead)",
    )
    setup.add_argument(
        "--use-system-ca",
        action="store_true",
        dest="use_system_ca",
        help="Trust certificates in the OS CA store (Node.js 24+; useful for self-signed certs already installed system-wide)",
    )
    setup.set_defaults(func=cmd_setup)

    status = sub.add_parser("status", help="Show config + binary + last fetch")
    status.set_defaults(func=cmd_status)

    sync = sub.add_parser("sync", help="Fetch secrets now and report what changed")
    sync.add_argument(
        "--apply",
        action="store_true",
        help="Actually export the secrets into the current process env (default: dry-run)",
    )
    sync.set_defaults(func=cmd_sync)

    disable = sub.add_parser("disable", help="Turn off the Bitwarden Vault integration")
    disable.set_defaults(func=cmd_disable)

    install = sub.add_parser(
        "install",
        help=f"Download and verify the pinned bw binary (v{bwv._BW_VERSION})",
    )
    install.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if a managed copy already exists",
    )
    install.set_defaults(func=cmd_install)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> int:
    console = Console()
    console.print(
        Panel.fit(
            "[bold]Bitwarden Vault setup[/bold]\n\n"
            "This wizard connects Hermes to your personal/org Bitwarden Vault.\n"
            "Secrets are stored as items in a designated folder (default: 'hermes').\n"
            "Each item name = env var name, item value = the secret.",
            border_style="cyan",
        )
    )

    # ------------------------------------------------------------------ binary
    console.print()
    console.print("[bold]Step 1[/bold]  Install the bw CLI")
    try:
        binary = bwv.find_bw(install_if_missing=False)
        if binary is None:
            console.print("  No bw on PATH — downloading…")
            binary = bwv.install_bw()
        version = _bw_version(binary)
        console.print(f"  [green]✓[/green] {binary}  ({version})")
    except Exception as exc:  # noqa: BLE001
        console.print(f"  [red]✗ Could not install bw: {exc}[/red]")
        console.print(
            "  Manual install: "
            "https://github.com/bitwarden/clients/releases"
        )
        return 1

    # ------------------------------------------------------------------- email
    console.print()
    console.print("[bold]Step 2[/bold]  Bitwarden account email")
    cfg = load_config()
    secrets_cfg = (cfg.setdefault("secrets", {})
                     .setdefault("bitwarden_vault", {}))

    email = (args.email or "").strip()
    if not email:
        existing = secrets_cfg.get("email", "")
        prompt = f"  Email [{existing}]: " if existing else "  Email: "
        email = console.input(prompt).strip() or existing
    if not email:
        console.print("  [red]Email is required, aborting.[/red]")
        return 1
    console.print(f"  [green]✓[/green] {email}")

    # ----------------------------------------------------------------- server
    console.print()
    console.print("[bold]Step 3[/bold]  Server configuration")
    server_url = (args.server_url or "").strip() if args.server_url else ""
    if not server_url:
        existing_url = secrets_cfg.get("server_url", "")
        default_label = existing_url if existing_url else "https://vault.bitwarden.com"
        url_input = console.input(
            f"  Server URL [{default_label}]: "
        ).strip()
        server_url = url_input or existing_url

    if server_url:
        console.print(f"  [green]✓[/green] using {server_url}")
    else:
        console.print(
            "  [green]✓[/green] using default (https://vault.bitwarden.com)"
        )

    # -------------------------------------------------------------------- TLS
    console.print()
    console.print("[bold]Step 3b[/bold]  TLS certificate configuration")
    # Collect ca_cert
    ca_cert = (getattr(args, "ca_cert", None) or "").strip()
    insecure_tls = bool(getattr(args, "insecure", False))
    use_system_ca = bool(getattr(args, "use_system_ca", False))
    if not ca_cert and not insecure_tls and not use_system_ca:
        existing_ca = secrets_cfg.get("ca_cert", "")
        existing_sys_ca = bool(secrets_cfg.get("use_system_ca", False))
        default_label = existing_ca if existing_ca else "(none)"
        ca_input = console.input(
            f"  CA certificate path (PEM) for self-signed TLS [{default_label}]: ",
            markup=False,
        ).strip()
        ca_cert = ca_input or existing_ca
        if not ca_cert and not existing_sys_ca:
            sys_ca_input = console.input(
                "  Use OS trust store (--use-system-ca, Node 24+)? [y/N]: "
            ).strip().lower()
            use_system_ca = sys_ca_input in ("y", "yes")
        elif existing_sys_ca and not ca_cert:
            use_system_ca = existing_sys_ca

    if ca_cert:
        ca_cert = str(Path(ca_cert).expanduser())
        if not Path(ca_cert).is_file():
            from rich.markup import escape as _escape
            console.print(
                f"  [red]✗ CA cert file not found: {_escape(ca_cert)}[/red]\n"
                "  [yellow]Provide the absolute path to a PEM file, or leave blank to skip.[/yellow]"
            )
            return 1
        from rich.markup import escape as _escape
        console.print(f"  [green]✓[/green] CA cert: {_escape(ca_cert)}")
    elif insecure_tls:
        console.print(
            "  [yellow]⚠ TLS verification disabled — use only on trusted networks.[/yellow]"
        )
    elif use_system_ca:
        console.print("  [green]✓[/green] Using OS trust store (--use-system-ca)")
    else:
        console.print("  [green]✓[/green] Using system default CA bundle")

    tls_env = bwv._tls_env_vars(ca_cert, insecure_tls, use_system_ca)

    # ----------------------------------------------------------------- login check
    console.print()
    console.print("[bold]Step 4[/bold]  Login & master password")

    # Configure server first if needed
    if server_url:
        bwv._configure_server(binary, server_url, tls_env=tls_env)

    # Check if already logged in
    status = bwv._check_status(binary, tls_env=tls_env)
    vault_status = status.get("status", "unauthenticated")

    if vault_status == "unauthenticated":
        console.print("  Not logged in — running `bw login`...")
        console.print(
            "  [yellow]Note: If 2FA is enabled, you'll be prompted for it.[/yellow]"
        )
        # Interactive login — we can't do this fully non-interactively with 2FA
        login_result = _interactive_login(binary, email, console, tls_env=tls_env)
        if not login_result:
            return 1
        console.print("  [green]✓[/green] Logged in successfully")
    else:
        console.print(f"  [green]✓[/green] Already logged in (status: {vault_status})")

    # ----------------------------------------------------------- master password
    console.print()
    console.print("[bold]Step 5[/bold]  Store master password for automated unlock")
    password_storage = secrets_cfg.get("password_storage", "auto")

    master_pw = masked_secret_prompt("  Master password: ").strip()
    if not master_pw:
        console.print("  [red]Empty password, aborting.[/red]")
        return 1

    # Verify the password works by trying to unlock
    console.print("  Verifying unlock...")
    import tempfile
    fd, pw_file = tempfile.mkstemp(prefix=".hermes_bw_test_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(master_pw)
        os.chmod(pw_file, 0o600)

        proc = bwv._run_bw(binary, ["unlock", "--passwordfile", pw_file], env_extra=tls_env)
    finally:
        try:
            os.unlink(pw_file)
        except OSError:
            pass

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        console.print(f"  [red]✗ Unlock failed: {err[:200]}[/red]")
        console.print("  [yellow]Is the master password correct?[/yellow]")
        return 1

    session = proc.stdout.strip()
    console.print("  [green]✓[/green] Unlock verified")

    # Store password
    from hermes_constants import get_hermes_home
    home_path = get_hermes_home()
    try:
        method = bwv.store_master_password(
            email, master_pw, password_storage, home_path
        )
        console.print(f"  [green]✓[/green] Password stored via {method}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"  [red]✗ Failed to store password: {exc}[/red]")
        return 1

    # ------------------------------------------------------------------- folder
    console.print()
    console.print("[bold]Step 6[/bold]  Select vault folder")
    folder_name = (args.folder or "").strip() if args.folder else ""

    if not folder_name:
        # List existing folders
        folders: list = []
        try:
            folders = bwv._list_folders(binary, session, tls_env=tls_env)
            if folders:
                table = Table(show_header=True, header_style="bold")
                table.add_column("#", style="cyan", width=4)
                table.add_column("Name")
                for i, f in enumerate(folders, 1):
                    name = f.get("name") or "(unnamed)"
                    table.add_row(str(i), name)
                console.print(table)
                console.print(
                    "  [dim]Enter a number to pick from the list, "
                    "or type any name to use/create that folder.[/dim]"
                )
        except Exception:  # noqa: BLE001
            folders = []

        existing_folder = secrets_cfg.get("folder_name", "hermes")
        folder_input = console.input(
            f"  Folder name or # [{existing_folder}]: "
        ).strip()

        if not folder_input:
            folder_name = existing_folder
        elif folder_input.isdigit():
            idx = int(folder_input) - 1
            if 0 <= idx < len(folders):
                folder_name = folders[idx].get("name") or existing_folder
            else:
                console.print(
                    f"  [red]Number {folder_input} is out of range.[/red]"
                )
                return 1
        else:
            folder_name = folder_input

    # Verify folder exists
    folder_id = bwv._find_folder_id(binary, session, folder_name, tls_env=tls_env)
    if folder_id is None:
        console.print(
            f"  [yellow]Folder '{folder_name}' not found.[/yellow]"
        )
        create = console.input("  Create it? [Y/n]: ").strip().lower()
        if create in ("", "y", "yes"):
            folder_id = _create_folder(binary, session, folder_name, console, tls_env=tls_env)
            if folder_id is None:
                return 1
        else:
            console.print("  [red]No folder selected, aborting.[/red]")
            return 1

    console.print(f"  [green]✓[/green] Using folder '{folder_name}' ({folder_id})")

    # ------------------------------------------------------------------- test
    console.print()
    console.print("[bold]Step 7[/bold]  Test fetch")
    try:
        items = bwv._list_items_in_folder(binary, session, folder_id, tls_env=tls_env)
    except Exception as exc:  # noqa: BLE001
        console.print(f"  [red]✗ Fetch failed: {exc}[/red]")
        return 1

    if not items:
        console.print(
            "  [yellow]Folder is empty — add items with names like "
            "OPENAI_API_KEY and their values as passwords or secure notes.[/yellow]"
        )
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name", style="cyan")
        table.add_column("Type")
        table.add_column("Status")
        for item in items:
            name = item.get("name", "?")
            item_type = item.get("type")
            type_label = "Login" if item_type == 1 else ("Secure Note" if item_type == 2 else f"type={item_type}")
            value = bwv._extract_secret_value(item)
            if value is None:
                status = "[yellow]unsupported type[/yellow]"
            elif not bwv._is_valid_env_name(name):
                status = "[yellow]invalid env name[/yellow]"
            elif os.environ.get(name):
                status = "[yellow]already set in env[/yellow]"
            else:
                status = "[green]new[/green]"
            table.add_row(name, type_label, status)
        console.print(table)

    # ------------------------------------------------------------------- save
    secrets_cfg["enabled"] = True
    secrets_cfg["email"] = email
    secrets_cfg["folder_name"] = folder_name
    secrets_cfg["server_url"] = server_url
    secrets_cfg["ca_cert"] = ca_cert
    secrets_cfg["insecure_tls"] = insecure_tls
    secrets_cfg["use_system_ca"] = use_system_ca
    secrets_cfg.setdefault("cache_ttl_seconds", 86400)
    secrets_cfg.setdefault("override_existing", False)
    secrets_cfg.setdefault("auto_install", True)
    secrets_cfg.setdefault("password_storage", password_storage)
    secrets_cfg.setdefault("org_id", "")
    save_config(cfg)

    console.print()
    console.print(
        "[green]✓ Bitwarden Vault is enabled.[/green]  "
        "Secrets will be pulled at the start of every Hermes process."
    )
    console.print(
        "  Status:  [cyan]hermes secrets bitwarden-vault status[/cyan]\n"
        "  Refresh: [cyan]hermes secrets bitwarden-vault sync[/cyan]\n"
        "  Disable: [cyan]hermes secrets bitwarden-vault disable[/cyan]"
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    console = Console()
    cfg = load_config()
    bwv_cfg = (cfg.get("secrets") or {}).get("bitwarden_vault") or {}

    enabled = bool(bwv_cfg.get("enabled"))
    email = bwv_cfg.get("email", "")
    folder_name = bwv_cfg.get("folder_name", "hermes")
    server_url = str(bwv_cfg.get("server_url", "") or "").strip()
    ca_cert = str(bwv_cfg.get("ca_cert", "") or "").strip()
    insecure_tls = bool(bwv_cfg.get("insecure_tls", False))
    use_system_ca = bool(bwv_cfg.get("use_system_ca", False))
    password_storage = bwv_cfg.get("password_storage", "auto")
    org_id = bwv_cfg.get("org_id", "")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("", style="bold")
    table.add_column("")
    table.add_row("Enabled", _yn(enabled))
    table.add_row("Email", email or "[dim](unset)[/dim]")
    table.add_row("Folder", folder_name)
    table.add_row(
        "Server URL",
        server_url or "[dim]default (https://vault.bitwarden.com)[/dim]",
    )
    from rich.markup import escape as _escape
    table.add_row(
        "CA certificate",
        _escape(ca_cert) if ca_cert else "[dim]system default[/dim]",
    )
    table.add_row(
        "Use OS trust store",
        "[green]yes[/green]" if use_system_ca else "[dim]no[/dim]",
    )
    table.add_row(
        "Insecure TLS",
        "[yellow]yes (verification disabled)[/yellow]" if insecure_tls else "[dim]no[/dim]",
    )
    table.add_row("Password storage", password_storage)
    table.add_row("Organization ID", org_id or "[dim](personal vault)[/dim]")
    table.add_row("Override existing", _yn(bool(bwv_cfg.get("override_existing", False))))
    table.add_row("Cache TTL (s)", str(bwv_cfg.get("cache_ttl_seconds", 86400)))
    table.add_row("Auto-install", _yn(bool(bwv_cfg.get("auto_install", True))))

    binary = bwv.find_bw(install_if_missing=False)
    if binary:
        table.add_row("bw binary", f"{binary} ({_bw_version(binary)})")
    else:
        table.add_row("bw binary", "[yellow]not installed[/yellow]")

    # Check if password is stored
    if email:
        from hermes_constants import get_hermes_home
        home_path = get_hermes_home()
        pw = bwv._read_master_password(email, password_storage, home_path)
        table.add_row("Password stored", _yn(pw is not None))
    else:
        table.add_row("Password stored", "[dim]n/a[/dim]")

    # Disk cache info
    from hermes_constants import get_hermes_home
    cache_path = bwv._disk_cache_path(get_hermes_home())
    if cache_path.exists():
        import json
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
            fetched_at = cache_data.get("fetched_at")
            secrets_count = len(cache_data.get("secrets", {}))
            if fetched_at:
                import time
                age = int(time.time() - fetched_at)
                table.add_row("Cache", f"{secrets_count} secrets, {age}s ago")
            else:
                table.add_row("Cache", f"{secrets_count} secrets")
        except (OSError, json.JSONDecodeError, ValueError):
            table.add_row("Cache", "[dim]unreadable[/dim]")
    else:
        table.add_row("Cache", "[dim]empty[/dim]")

    console.print(Panel(table, title="Bitwarden Vault", border_style="cyan"))

    if not enabled:
        console.print("\n  Run [cyan]hermes secrets bitwarden-vault setup[/cyan] to enable.")
        return 0
    if not email:
        console.print(
            "\n  [yellow]Enabled but no email configured — Hermes will skip "
            "vault pull and warn on next startup.[/yellow]"
        )
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    console = Console()
    cfg = load_config()
    bwv_cfg = (cfg.get("secrets") or {}).get("bitwarden_vault") or {}
    if not bwv_cfg.get("enabled"):
        console.print(
            "[yellow]Bitwarden Vault integration is disabled.  Run "
            "`hermes secrets bitwarden-vault setup` first.[/yellow]"
        )
        return 1

    email = bwv_cfg.get("email", "")
    if not email:
        console.print("[red]No email configured.[/red]")
        return 1

    folder_name = bwv_cfg.get("folder_name", "hermes")
    server_url = str(bwv_cfg.get("server_url", "") or "").strip()
    identity_url = str(bwv_cfg.get("identity_url", "") or "").strip()
    api_url = str(bwv_cfg.get("api_url", "") or "").strip()
    org_id = str(bwv_cfg.get("org_id", "") or "").strip()
    password_storage = bwv_cfg.get("password_storage", "auto")
    ca_cert = str(bwv_cfg.get("ca_cert", "") or "").strip()
    insecure_tls = bool(bwv_cfg.get("insecure_tls", False))
    use_system_ca = bool(bwv_cfg.get("use_system_ca", False))

    from hermes_constants import get_hermes_home
    home_path = get_hermes_home()

    try:
        secrets, warnings = bwv.fetch_vault_secrets(
            email=email,
            folder_name=folder_name,
            use_cache=False,
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
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Fetch failed: {exc}[/red]")
        return 1

    if not secrets:
        console.print("[yellow]No secrets in folder.[/yellow]")
        return 0

    override = bool(bwv_cfg.get("override_existing", False)) or args.apply
    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Action")
    applied = 0
    for key in sorted(secrets):
        already = bool(os.environ.get(key))
        if already and not override:
            table.add_row(key, "[dim]skip (already set)[/dim]")
            continue
        if args.apply:
            os.environ[key] = secrets[key]
            applied += 1
            table.add_row(key, "[green]exported[/green]" + (" (overrode)" if already else ""))
        else:
            table.add_row(key, "[green]would export[/green]" + (" (overrides)" if already else ""))

    console.print(table)
    for w in warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")

    if not args.apply:
        console.print(
            "\n  This was a dry-run — secrets are picked up automatically on the "
            "next [cyan]hermes[/cyan] invocation.  Re-run with [cyan]--apply[/cyan] "
            "to export into the current shell instead."
        )
    else:
        console.print(f"\n  [green]Exported {applied} secret(s) into current process.[/green]")
    return 0


def cmd_disable(args: argparse.Namespace) -> int:
    console = Console()
    cfg = load_config()
    bwv_cfg = (cfg.setdefault("secrets", {})
                  .setdefault("bitwarden_vault", {}))
    bwv_cfg["enabled"] = False
    save_config(cfg)
    console.print(
        "[green]Disabled.[/green]  Bitwarden Vault secrets will NOT be pulled on "
        "the next Hermes invocation.\n"
        "  Your master password is still stored — remove it manually from "
        "the keyring or ~/.hermes/.bw_master_password if desired."
    )
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    console = Console()
    try:
        path = bwv.install_bw(force=bool(args.force))
        console.print(f"[green]✓[/green] {path}  ({_bw_version(path)})")
        return 0
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Install failed: {exc}[/red]")
        return 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _yn(b: bool) -> str:
    return "[green]yes[/green]" if b else "[dim]no[/dim]"


def _bw_version(binary: Path) -> str:
    try:
        res = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return (res.stdout or res.stderr).strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "version unknown"


def _interactive_login(
    binary: Path, email: str, console: Console,
    tls_env: Optional[dict] = None,
) -> bool:
    """Run bw login interactively (handles 2FA prompts)."""
    import sys

    cmd = [str(binary), "login", email, "--nointeraction"]
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if tls_env:
        env.update(tls_env)

    # For interactive login with potential 2FA, we need to let
    # stdin/stdout pass through
    console.print(f"  Running: bw login {email}")
    console.print("  [dim](Follow prompts in terminal)[/dim]")

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            timeout=120,
            # Let stdin/stdout pass through for 2FA
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        console.print("  [red]Login timed out.[/red]")
        return False
    except OSError as exc:
        console.print(f"  [red]Login failed: {exc}[/red]")
        return False


def _create_folder(
    binary: Path, session: str, folder_name: str, console: Console,
    tls_env: Optional[dict] = None,
) -> Optional[str]:
    """Create a new folder in the vault and return its ID."""
    import base64
    import json

    # bw expects the folder encoded as a JSON object with "name"
    folder_json = json.dumps({"name": folder_name})
    encoded = base64.b64encode(folder_json.encode("utf-8")).decode("ascii")

    cmd = [str(binary), "create", "folder", encoded, "--nointeraction", "--session", session]
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if tls_env:
        env.update(tls_env)

    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        console.print(f"  [red]Failed to create folder: {exc}[/red]")
        return None

    if proc.returncode != 0:
        console.print(f"  [red]Failed to create folder: {proc.stderr.strip()[:200]}[/red]")
        return None

    try:
        result = json.loads(proc.stdout.strip())
        folder_id = result.get("id")
        if folder_id:
            console.print(f"  [green]✓[/green] Created folder '{folder_name}'")
            return folder_id
    except (json.JSONDecodeError, ValueError):
        pass

    console.print("  [red]Could not parse folder creation result.[/red]")
    return None
