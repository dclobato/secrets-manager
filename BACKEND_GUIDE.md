# Extending SecretsManager (Maintainers)

This document is for maintainers. End users can only use the built-in behavior unless they modify the package.

## Overview

SecretsManager is intentionally compact. Extension points are:

- Key derivation parameters (iterations, salt normalization)
- Audit event payloads
- Persistence helpers for loading/saving keys

## Adding a New Derivation Strategy

1) Implement a new helper in `src/secrets_manager/utils.py`.
2) Wire it into `SecretsConfig` and `SecretsManager`.
3) Add tests in `tests/` for the new strategy.
4) Update `README.md` and `INSTALLATION_GUIDE.md` if user-facing.

## Adding New Audit Events

1) Update the audit emission in `src/secrets_manager/manager.py`.
2) Keep the event names stable.
3) Add tests asserting payload shape.

## Documentation Updates

If behavior changes:

- Update `README.md` and `INSTALLATION_GUIDE.md`.
- Add an entry to `CHANGELOG.md`.
