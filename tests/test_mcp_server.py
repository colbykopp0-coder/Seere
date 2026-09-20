import os
from pathlib import Path

import pytest

from seere_mcp import server
from seere_sdk import SeereScanner


def test_mcp_server_object_exists():
    assert server.mcp is not None


def test_allowed_scope_defaults_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SEERE_ALLOWED_ROOTS", raising=False)

    assert server._authorize(".") == tmp_path.resolve()

    outside = tmp_path.parent.resolve()
    with pytest.raises(ValueError):
        server._authorize(str(outside))


def test_allowed_scope_respects_config(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()

    monkeypatch.setenv("SEERE_ALLOWED_ROOTS", str(allowed))

    assert server._authorize(str(allowed)) == allowed.resolve()

    with pytest.raises(ValueError):
        server._authorize(str(denied))


def test_scanner_redacts_synthetic_secret(tmp_path):
    synthetic = "sk-proj-EXAMPLEONLYNOTREAL12345678901234567890"
    (tmp_path / ".env").write_text(
        f"OPENAI_API_KEY={synthetic}\n",
        encoding="utf-8",
    )

    report = SeereScanner().scan(tmp_path)

    assert report.findings
    assert any(f.provider == "openai" for f in report.findings)
    assert all(synthetic not in f.preview for f in report.findings)
