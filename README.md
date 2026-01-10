# SecretsManager

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Thread-safe secrets manager with Fernet encryption, multi-version key rotation, and PBKDF2 key derivation (no third-party time dependency).

## Features

- **Fernet Encryption**: AES-128 CBC + HMAC
- **Key Rotation**: multi-version key management with fallback
- **PBKDF2 Derivation**: key derivation from passwords
- **Salt Integrity**: optional SHA256 validation
- **Thread-Safe**: RLock-protected caches
- **Auditability**: optional audit callbacks
- **Statistics**: basic metrics tracking
- **Environment Persistence**: save/load keys from `.env` files

## Installation

### Makefile (Linux/macOS) vs Windows

- `Makefile` targets Linux/macOS.
- On Windows, use `Makefile.windows`:
  ```bash
  make -f Makefile.windows install-dev
  make -f Makefile.windows test
  make -f Makefile.windows check
  ```

### Core Install

```bash
uv add SecretsManager
```

### For Development

```bash
uv sync --extra dev
```

## Quick Start

```python
from secrets_manager import SecretsConfig, SecretsManager

config = SecretsConfig(
    keys={
        "v1": {
            "key": "my-secret-password",
            "salt": "random-salt-value",
        }
    },
    active_version="v1",
)

manager = SecretsManager(config)

version, ciphertext = manager.encrypt(b"sensitive data")
version, plaintext = manager.decrypt(ciphertext)
```

## Key Rotation Example

```python
from secrets_manager import SecretsConfig, SecretsManager

config = SecretsConfig(
    keys={"v1": {"key": "old-password", "salt": "old-salt"}},
    active_version="v1",
)

manager = SecretsManager(config)
_, ciphertext_v1 = manager.encrypt(b"important data")

manager.rotate_to_new_version(
    new_version="v2",
    new_key="new-password",
    new_salt=b"new-salt",
)

_, ciphertext_v2 = manager.encrypt(b"new data")
manager.decrypt(ciphertext_v1)
manager.decrypt(ciphertext_v2)
```

## Advanced Features

### Salt Integrity Validation

```python
import hashlib

salt = b"my-salt"
salt_hash = hashlib.sha256(salt).hexdigest()

config = SecretsConfig(
    keys={"v1": {"key": "password", "salt": salt, "salt_hash": salt_hash}},
    active_version="v1",
    verify_salt_integrity=True,
)
```

### Audit Logging

```python
def audit_callback(event: str, metadata: dict):
    print(f"[AUDIT] {event}: {metadata}")

config = SecretsConfig(
    keys={"v1": {"key": "pass", "salt": "salt"}},
    active_version="v1",
    audit_callback=audit_callback,
)
```

### Statistics

```python
stats = manager.get_statistics()
```

### Environment File Persistence

```python
manager.rotate_to_new_version(
    new_version="v2",
    new_key="new-key",
    new_salt=b"new-salt",
    persist_to_file=".env.secrets",
)
```

## Configuration Options

```python
@dataclass
class SecretsConfig:
    keys: Dict[str, Dict[str, Any]]
    active_version: str
    kdf_iterations: int = 100_000
    verify_salt_integrity: bool = True
    audit_callback: Optional[Callable] = None
    logger: Optional[logging.Logger] = None
```

## Requirements

- Python >= 3.11
- cryptography >= 41.0.0

## Contributing

Contributions are welcome. See `CONTRIBUTING.md` and `INSTALLATION_GUIDE.md` for local setup and checks.

## License

This project is licensed under the MIT License. See `LICENSE`.

## Author

**Daniel Correa Lobato**
- Website: [sites.lobato.org](https://sites.lobato.org)
- Email: daniel@lobato.org

