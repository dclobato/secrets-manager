# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.0]
- Add SecretsConfig.from_file() and SecretsConfig.to_file()
- Add example for .env load/save workflow
- Normalize salts to bytes and document base64 storage in .env
- Add python-dotenv parsing and checksum validation for .env files
- Add best-effort file locking when writing .env with append=True
- Document security guidance for .env handling

## [0.1.0]
- Initial release

[Unreleased]: https://github.com/dclobato/secrets-manager/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/dclobato/secrets-manager/releases/tag/v1.0.0
[0.1.0]: https://github.com/dclobato/secrets-manager/releases/tag/v0.1.0
