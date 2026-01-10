"""SecretsManager - Thread-safe secrets management with key rotation.

Este pacote fornece gerenciamento de segredos com:
- Criptografia Fernet (AES-128 CBC + HMAC)
- Rotação de chaves multi-versão
- Derivação PBKDF2-HMAC-SHA256
- Cache thread-safe
- Auditoria configurável
"""

from .config import KeyConfiguration, SecretsConfig
from .manager import SecretsManager, SecretsManagerError
from .utils import normalize_salt, normalize_version

__version__ = "0.1.0"

__all__ = [
    # Classes principais
    "SecretsManager",
    "SecretsManagerError",
    # Configuração
    "SecretsConfig",
    "KeyConfiguration",
    # Utilidades
    "normalize_salt",
    "normalize_version",
]
