# Roadmap: Key Management Enhancements

This roadmap documents potential next steps. These are **not implemented** today.

## Goals

- Support multiple KDF strategies (scrypt, argon2)
- Add key metadata for rotation schedules
- Provide CLI helpers for rotation

## Proposed Features

### 1) Multiple KDFs

Allow selecting KDF via config with sane defaults and test coverage.

### 2) Key Metadata

Include creation time and rotation hints per version.

### 3) CLI Utilities

Provide a small CLI for generating salts and rotating keys.

## Next Step (Recommended)

Ship a minor release with CLI utilities and add documentation.
