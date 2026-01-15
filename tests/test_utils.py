"""Testes para utils."""

import base64
import sys
import types
from io import StringIO

import pytest

from secrets_manager import normalize_salt, normalize_version
from secrets_manager.utils import ENV_CHECKSUM_KEY, compute_env_checksum, escape_env_value, parse_env_stream
import secrets_manager.utils as utils


def test_normalize_salt():
    """Testa normalização de salt em vários formatos."""
    salt_bytes = b"salt123"
    salt_hex = salt_bytes.hex()
    salt_b64 = base64.urlsafe_b64encode(salt_bytes).decode("ascii")

    assert normalize_salt(salt_bytes) == salt_bytes
    assert normalize_salt(salt_hex) == salt_bytes
    assert normalize_salt(salt_b64) == salt_bytes
    assert normalize_salt("salt123") == salt_bytes  # UTF8 fallback

    with pytest.raises(TypeError):
        normalize_salt(123)


def test_normalize_version():
    """Testa normalização de versão."""
    assert normalize_version("V1") == "v1"
    assert normalize_version("v1") == "v1"
    assert normalize_version("") == ""


def test_escape_env_value():
    """Testa escape de valores para .env."""
    assert escape_env_value('value"quoted') == 'value\\"quoted'
    assert escape_env_value(r"value\path") == r"value\\path"


def test_compute_env_checksum_ignores_checksum_key():
    """Testa que checksum ignora o próprio campo."""
    data = {
        "A": "1",
        "B": "2",
        ENV_CHECKSUM_KEY: "ignore",
    }
    checksum = compute_env_checksum(data)
    assert checksum == compute_env_checksum({"A": "1", "B": "2"})


def test_compute_env_checksum_ignores_none_values():
    """Testa que checksum ignora valores None."""
    data = {"A": "1", "B": None}
    assert compute_env_checksum(data) == compute_env_checksum({"A": "1"})


def test_parse_env_stream_with_quotes_and_hash():
    """Testa parser de .env com aspas e # no valor."""
    stream = StringIO('KEY="value#123"\nOTHER="value\\"quoted"\n')
    data = parse_env_stream(stream)
    assert data["KEY"] == "value#123"
    assert data["OTHER"] == 'value"quoted'


def test_lock_unlock_posix(monkeypatch):
    """Testa lock/unlock no caminho posix."""
    calls = []

    fake_fcntl = types.SimpleNamespace(
        LOCK_EX=1,
        LOCK_UN=2,
        flock=lambda fd, op: calls.append((fd, op)),
    )

    monkeypatch.setattr(utils.os, "name", "posix", raising=False)
    monkeypatch.setitem(sys.modules, "fcntl", fake_fcntl)

    class DummyFile:
        def fileno(self):
            return 99

        def seek(self, *args, **kwargs):
            return None

    dummy = DummyFile()
    utils._lock_file(dummy)
    utils._unlock_file(dummy)

    assert calls == [(99, 1), (99, 2)]
