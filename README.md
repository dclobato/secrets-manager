# SecretsManager

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Thread-safe secrets manager with Fernet encryption, multi-version key rotation, and PBKDF2 key derivation (no third-party time dependency).

## Features

- **Fernet Encryption**: AES-128 CBC + HMAC
- **Key Rotation**: multi-version key management with fallback
- **PBKDF2 Derivation**: key derivation from passwords
- **Salt Integrity**: optional SHA256 validation
- **Thread-Safe**: RLock-protected caches and atomic statistics counters
- **Secure Memory Management**: Uses `bytearray` for keys with cleanup support
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

## Security Features

### Secure Key Storage with bytearray

SecretsManager uses `bytearray` instead of immutable `str` for storing cryptographic keys in memory. This provides:

- **Memory Overwriting**: Keys can be securely zeroed when no longer needed
- **Reduced Exposure Window**: Minimizes risk of key exposure in memory dumps
- **Best-Effort Security**: While Python's garbage collector limitations mean we can't guarantee complete removal, this approach significantly reduces the attack surface

### Memory Cleanup

Always call `cleanup()` when you're done with the SecretsManager to securely clear sensitive data:

```python
from secrets_manager import SecretsConfig, SecretsManager

config = SecretsConfig(
    keys={"v1": {"key": "my-secret-password", "salt": "random-salt-value"}},
    active_version="v1",
)

manager = SecretsManager(config)

# ... use manager ...

# Securely clear keys from memory
manager.cleanup()
```

**When to call cleanup():**
- Before shutting down your application
- After key rotation in high-security environments
- When disposing of SecretsManager instances

### Thread-Safe Statistics

All statistics tracking uses atomic counters to prevent race conditions under concurrent access:

```python
stats = manager.get_statistics()
# Accurate even with multiple threads calling encrypt/decrypt simultaneously
print(f"Encryptions: {stats['encryptions']}")
print(f"Decryptions: {stats['decryptions']}")
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

# Clean up when done
manager.cleanup()
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

# Clean up when done
manager.cleanup()
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

