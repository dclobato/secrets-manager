"""Funções auxiliares para o SecretsManager."""

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, TextIO

import base64

from dotenv import dotenv_values


ENV_CHECKSUM_KEY = "ENCRYPTION_ENV_CHECKSUM"


def escape_env_value(value: str) -> str:
    """Escapa valores para escrita segura em arquivos .env."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def compute_env_checksum(values: Mapping[str, str]) -> str:
    """Calcula checksum SHA256 determinístico para um mapeamento .env."""
    items = []
    for key in sorted(values):
        if key == ENV_CHECKSUM_KEY:
            continue
        value = values.get(key)
        if value is None:
            continue
        items.append(f"{key}={value}")
    payload = "\n".join(items).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def parse_env_stream(stream: TextIO) -> Dict[str, str]:
    """Parseia um stream .env usando python-dotenv."""
    data = dotenv_values(stream=stream)
    return {key: value for key, value in data.items() if value is not None}


def parse_env_file(path: Path) -> Dict[str, str]:
    """Parseia um arquivo .env usando python-dotenv."""
    with path.open("r", encoding="utf-8", errors="strict") as f:
        return parse_env_stream(f)


def _lock_file(file_handle: TextIO) -> None:
    if os.name == "nt":
        import msvcrt

        file_handle.seek(0)
        msvcrt.locking(file_handle.fileno(), msvcrt.LK_LOCK, 1)
        return

    import fcntl

    fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(file_handle: TextIO) -> None:
    if os.name == "nt":
        import msvcrt

        file_handle.seek(0)
        msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def locked_file(path: Path) -> Iterator[TextIO]:
    """Abre o arquivo e aplica lock exclusivo enquanto estiver em uso."""
    file_handle = path.open("a+", encoding="utf-8", errors="strict")
    _lock_file(file_handle)
    try:
        yield file_handle
    finally:
        _unlock_file(file_handle)
        file_handle.close()


def normalize_salt(salt: Any) -> bytes:
    """Converte salt de diversos formatos para bytes.

    Suporta:
    - bytes (retorna direto)
    - string hexadecimal (e.g., "73616c74")
    - string base64 (e.g., "c2FsdA==")
    - string UTF-8 (fallback)

    Args:
        salt: Salt em qualquer formato suportado

    Returns:
        bytes: Salt convertido para bytes

    Raises:
        TypeError: Se salt não for str ou bytes

    Examples:
        >>> normalize_salt(b"salt")
        b'salt'
        >>> normalize_salt("73616c74")  # hex
        b'salt'
        >>> normalize_salt("c2FsdA==")  # base64
        b'salt'
        >>> normalize_salt("salt")  # utf-8
        b'salt'
    """
    if isinstance(salt, bytes):
        return salt

    if not isinstance(salt, str):
        raise TypeError(f"Salt deve ser str ou bytes, recebido: {type(salt)}")

    # Tenta hex (deve ter comprimento par)
    if len(salt) % 2 == 0:
        try:
            return bytes.fromhex(salt)
        except ValueError:
            pass

    # Tenta base64
    try:
        return base64.urlsafe_b64decode(salt.encode("ascii"))
    except Exception:
        pass

    # Fallback: UTF-8 direto
    return salt.encode("utf-8")


def normalize_version(version: str) -> str:
    """Normaliza versão para lowercase para compatibilidade cross-platform.

    Args:
        version: Versão a ser normalizada

    Returns:
        str: Versão em lowercase

    Examples:
        >>> normalize_version("V1")
        'v1'
        >>> normalize_version("v1")
        'v1'
    """
    return version.lower() if version else version
