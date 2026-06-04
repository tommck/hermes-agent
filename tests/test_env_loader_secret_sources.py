"""Tests for the secret-source tracking in ``hermes_cli.env_loader``.

These cover the small public surface that lets `hermes model` / `hermes setup`
label detected credentials with their origin ("from Bitwarden") so users
don't see an unexplained "credentials ✓" line when their .env is empty.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hermes_cli import env_loader  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_sources():
    """Each test starts with a clean source map and applied-home guard."""
    env_loader._SECRET_SOURCES.clear()
    env_loader.reset_secret_source_cache()
    yield
    env_loader._SECRET_SOURCES.clear()
    env_loader.reset_secret_source_cache()


def test_get_secret_source_returns_none_for_untracked_var():
    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") is None


def test_get_secret_source_returns_label_for_tracked_var():
    env_loader._SECRET_SOURCES["ANTHROPIC_API_KEY"] = "bitwarden"
    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") == "bitwarden"


def test_format_secret_source_suffix_empty_for_untracked():
    # Credentials from .env or the shell shouldn't add noise — the
    # implicit case stays unlabeled.
    assert env_loader.format_secret_source_suffix("ANTHROPIC_API_KEY") == ""


def test_format_secret_source_suffix_bitwarden_uses_proper_name():
    env_loader._SECRET_SOURCES["ANTHROPIC_API_KEY"] = "bitwarden"
    assert (
        env_loader.format_secret_source_suffix("ANTHROPIC_API_KEY")
        == " (from Bitwarden)"
    )


def test_format_secret_source_suffix_generic_label_for_future_sources():
    # Future-proofing: a new secret source (e.g. "vault") should still
    # produce a sensible label without needing to edit every call site.
    env_loader._SECRET_SOURCES["OPENAI_API_KEY"] = "vault"
    assert (
        env_loader.format_secret_source_suffix("OPENAI_API_KEY")
        == " (from vault)"
    )


def test_apply_external_secret_sources_records_bitwarden_origin(tmp_path, monkeypatch):
    """End-to-end: when ``apply_bitwarden_secrets`` returns applied keys,
    they end up in ``_SECRET_SOURCES`` so the UI can label them."""

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden:\n"
        "    enabled: true\n"
        "    project_id: test-project\n"
        "    access_token_env: BWS_ACCESS_TOKEN\n",
        encoding="utf-8",
    )

    # Stub apply_bitwarden_secrets to return a synthetic FetchResult.
    from agent.secret_sources.bitwarden import FetchResult

    fake_result = FetchResult(
        secrets={"ANTHROPIC_API_KEY": "sk-ant-test"},
        applied=["ANTHROPIC_API_KEY"],
    )

    def _fake_apply(**_kwargs):
        return fake_result

    # The import inside _apply_external_secret_sources is lazy, so we
    # patch the *module attribute* it will pull in.
    import agent.secret_sources.bitwarden as bw_module

    monkeypatch.setattr(bw_module, "apply_bitwarden_secrets", _fake_apply)

    env_loader._apply_external_secret_sources(tmp_path)

    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") == "bitwarden"
    assert (
        env_loader.format_secret_source_suffix("ANTHROPIC_API_KEY")
        == " (from Bitwarden)"
    )


def test_apply_external_secret_sources_noop_when_disabled(tmp_path, monkeypatch):
    """Disabled Bitwarden config must not touch the source map."""

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden:\n"
        "    enabled: false\n",
        encoding="utf-8",
    )

    env_loader._apply_external_secret_sources(tmp_path)

    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") is None


def test_apply_external_secret_sources_dedupes_within_process(tmp_path, monkeypatch):
    """``load_hermes_dotenv()`` is called at module-import time from several
    hot modules (cli.py, hermes_cli/main.py, run_agent.py, ...).  The
    Bitwarden status line previously printed once per call — 3-5x per
    startup.  The applied-home guard must short-circuit subsequent calls
    so the heavy work (config re-parse, Bitwarden lookup, status print)
    runs exactly once per HERMES_HOME per process.
    """

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden:\n"
        "    enabled: true\n"
        "    project_id: test-project\n"
        "    access_token_env: BWS_ACCESS_TOKEN\n",
        encoding="utf-8",
    )

    from agent.secret_sources.bitwarden import FetchResult

    call_count = {"n": 0}

    def _fake_apply(**_kwargs):
        call_count["n"] += 1
        return FetchResult(
            secrets={"ANTHROPIC_API_KEY": "sk-ant-test"},
            applied=["ANTHROPIC_API_KEY"],
        )

    import agent.secret_sources.bitwarden as bw_module
    monkeypatch.setattr(bw_module, "apply_bitwarden_secrets", _fake_apply)

    # Five calls in a row, simulating module-import-time invocations from
    # cli.py, hermes_cli/main.py, run_agent.py, trajectory_compressor.py,
    # gateway/run.py.  Only the first should actually call the backend.
    for _ in range(5):
        env_loader._apply_external_secret_sources(tmp_path)

    assert call_count["n"] == 1, (
        "Bitwarden backend was called {} time(s); expected exactly 1 — "
        "the applied-home guard is broken.".format(call_count["n"])
    )

    # Source tracking still works after dedup.
    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") == "bitwarden"

    # reset_secret_source_cache() forces a fresh pull on the next call.
    env_loader.reset_secret_source_cache()
    env_loader._apply_external_secret_sources(tmp_path)
    assert call_count["n"] == 2


def test_vault_loaded_when_bsm_disabled(tmp_path, monkeypatch):
    """bitwarden_vault must be pulled even when bitwarden (BSM) is disabled.

    This is the gateway-with-Matrix scenario: BSM is disabled, vault is
    enabled, and Matrix secrets live in the vault.  The previous early-return
    on ``not bw_cfg.get("enabled")`` silently skipped the vault entirely.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden:\n"
        "    enabled: false\n"
        "  bitwarden_vault:\n"
        "    enabled: true\n"
        "    email: user@example.com\n"
        "    folder_name: hermes\n",
        encoding="utf-8",
    )

    from agent.secret_sources.bitwarden_vault import FetchResult as VaultFetchResult

    fake_result = VaultFetchResult(
        secrets={"MATRIX_ACCESS_TOKEN": "syt_fake_token"},
        applied=["MATRIX_ACCESS_TOKEN"],
    )

    def _fake_apply(**_kwargs):
        return fake_result

    import agent.secret_sources.bitwarden_vault as bwv_module
    monkeypatch.setattr(bwv_module, "apply_vault_secrets", _fake_apply)

    env_loader._apply_external_secret_sources(tmp_path)

    assert env_loader.get_secret_source("MATRIX_ACCESS_TOKEN") == "bitwarden_vault"
    assert (
        env_loader.format_secret_source_suffix("MATRIX_ACCESS_TOKEN")
        == " (from Bitwarden Vault)"
    )


def test_vault_source_label_tracked(tmp_path, monkeypatch):
    """Keys applied from the vault are labelled 'bitwarden_vault' in source map."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden_vault:\n"
        "    enabled: true\n"
        "    email: user@example.com\n",
        encoding="utf-8",
    )

    from agent.secret_sources.bitwarden_vault import FetchResult as VaultFetchResult

    fake_result = VaultFetchResult(
        secrets={
            "MATRIX_ACCESS_TOKEN": "syt_tok",
            "MATRIX_HOMESERVER": "https://matrix.example.org",
        },
        applied=["MATRIX_ACCESS_TOKEN", "MATRIX_HOMESERVER"],
    )

    import agent.secret_sources.bitwarden_vault as bwv_module
    monkeypatch.setattr(bwv_module, "apply_vault_secrets", lambda **_: fake_result)

    env_loader._apply_external_secret_sources(tmp_path)

    assert env_loader.get_secret_source("MATRIX_ACCESS_TOKEN") == "bitwarden_vault"
    assert env_loader.get_secret_source("MATRIX_HOMESERVER") == "bitwarden_vault"
    # BSM keys remain unlabelled
    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") is None


def test_bsm_and_vault_both_run_when_both_enabled(tmp_path, monkeypatch):
    """Both BSM and vault are called independently when both enabled."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden:\n"
        "    enabled: true\n"
        "    project_id: proj\n"
        "    access_token_env: BWS_ACCESS_TOKEN\n"
        "  bitwarden_vault:\n"
        "    enabled: true\n"
        "    email: user@example.com\n",
        encoding="utf-8",
    )

    from agent.secret_sources.bitwarden import FetchResult
    from agent.secret_sources.bitwarden_vault import FetchResult as VaultFetchResult

    bsm_calls = {"n": 0}
    vault_calls = {"n": 0}

    def _fake_bsm(**_):
        bsm_calls["n"] += 1
        return FetchResult(secrets={"OPENAI_API_KEY": "sk-bsm"}, applied=["OPENAI_API_KEY"])

    def _fake_vault(**_):
        vault_calls["n"] += 1
        return VaultFetchResult(secrets={"MATRIX_ACCESS_TOKEN": "syt_tok"}, applied=["MATRIX_ACCESS_TOKEN"])

    import agent.secret_sources.bitwarden as bw_module
    import agent.secret_sources.bitwarden_vault as bwv_module
    monkeypatch.setattr(bw_module, "apply_bitwarden_secrets", _fake_bsm)
    monkeypatch.setattr(bwv_module, "apply_vault_secrets", _fake_vault)

    env_loader._apply_external_secret_sources(tmp_path)

    assert bsm_calls["n"] == 1
    assert vault_calls["n"] == 1
    assert env_loader.get_secret_source("OPENAI_API_KEY") == "bitwarden"
    assert env_loader.get_secret_source("MATRIX_ACCESS_TOKEN") == "bitwarden_vault"
