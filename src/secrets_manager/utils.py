"""Funções auxiliares para o SecretsManager."""

import base64
from typing import Any


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
