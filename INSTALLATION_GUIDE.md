# SecretsManager - Installation and First Steps

## Project Structure

```
SecretsManager/
├── src/
│   └── secrets_manager/       # Package source code
│       ├── __init__.py        # Public exports
│       ├── config.py          # Configuration models
│       ├── manager.py         # Core manager
│       └── utils.py           # Helpers
├── tests/                     # Unit tests
├── examples/                  # Usage examples
├── pyproject.toml             # Project configuration
├── README.md                  # Main documentation
├── LICENSE                    # MIT license
├── CHANGELOG.md               # Release history
├── CONTRIBUTING.md            # Contributing guide
├── Makefile                   # Task automation (Linux/macOS)
└── Makefile.windows           # Task automation (Windows)
```

## Development Installation

### 1) Sync Dependencies with uv

```bash
cd SecretsManager
```

### 2) Install Dependencies

```bash
# Core install
uv sync

# Development (pytest, mypy, etc)
uv sync --extra dev
```

### 3) Run Tests

```bash
# Basic tests
uv run pytest

# Coverage
uv run pytest --cov=secrets_manager --cov-report=html

# Or use the Makefile
uv run make test
uv run make test-cov
```

### 4) Code Quality Checks

```bash
# Formatting
uv run make format

# Linting
uv run make lint

# Type checking
uv run make type-check

# All checks
uv run make check
```

## Testing the Package Locally

Create `test_local.py`:

```python
from secrets_manager import SecretsConfig, SecretsManager

config = SecretsConfig(
    keys={"v1": {"key": "k", "salt": "s"}},
    active_version="v1",
)

manager = SecretsManager(config)
version, ciphertext = manager.encrypt(b"data")
print(version, manager.decrypt(ciphertext))
```

Run:
```bash
uv run python test_local.py
```

## Publishing to PyPI

### 1) Update Version

Edit `src/secrets_manager/__init__.py` and `pyproject.toml`:

```python
__version__ = "0.1.1"
```

### 2) Update CHANGELOG

Document changes in `CHANGELOG.md`.

### 3) Tag the Release

```bash
git add .
git commit -m "Release v0.1.1"
git tag v0.1.1
git push origin main --tags
```

### 4) Build and Upload

```bash
uv build
uv publish
```

### 5) Installation Test

```bash
uv init
uv add SecretsManager
uv run python -c "from secrets_manager import SecretsManager; print('OK')"
```

## Next Steps

1. Validate encryption/decryption flows in your target app.
2. Configure audit logging if needed.
3. Publish when stable.

## Support

- Issues: https://github.com/dclobato/SecretsManager/issues
- Email: daniel@lobato.org
- Website: https://sites.lobato.org

