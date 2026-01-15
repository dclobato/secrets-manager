"""Testes para SecretsConfig."""

import errno
import hashlib
from contextlib import contextmanager

import pytest

from secrets_manager import KeyConfiguration, SecretsConfig
from secrets_manager.utils import ENV_CHECKSUM_KEY


def test_key_configuration_integrity():
    """Testa validação de integridade do hash do salt."""
    salt = b"salt-integrity"
    salt_hash = hashlib.sha256(salt).hexdigest()

    # Hash correto - não deve levantar exceção
    config = KeyConfiguration(version="1", key="k", salt=salt, salt_hash=salt_hash)
    assert config.salt == salt

    # Hash incorreto - deve levantar exceção
    with pytest.raises(ValueError, match="Integridade do salt comprometida"):
        KeyConfiguration(version="1", key="k", salt=salt, salt_hash="hash-errado")


def test_key_configuration_converts_str_key():
    """Testa conversão automática de key str para bytearray."""
    config = KeyConfiguration(version="1", key="secret", salt=b"salt")
    assert isinstance(config.key, bytearray)
    assert bytes(config.key) == b"secret"


def test_secrets_config_validation():
    """Testa validação de SecretsConfig."""
    # Config válida
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": b"s"}}, active_version="v1")
    assert config.active_version == "v1"
    assert isinstance(config.keys["v1"]["salt"], bytes)

    # Config vazia
    with pytest.raises(ValueError, match="Pelo menos uma chave"):
        SecretsConfig(keys={}, active_version="v1")

    # Versão ativa inexistente
    with pytest.raises(ValueError, match="Versão ativa .* não existe"):
        SecretsConfig(keys={"v1": {"key": "k", "salt": b"s"}}, active_version="v2")

    # Config incompleta (faltando salt)
    with pytest.raises(ValueError, match="deve conter 'key' e 'salt'"):
        SecretsConfig(keys={"v1": {"key": "k"}}, active_version="v1")


def test_secrets_config_validation_invalid_entry_type():
    """Testa erro quando a entrada da chave não é um dicionário."""
    with pytest.raises(ValueError, match="deve ser um dicionário"):
        SecretsConfig(keys={"v1": "invalid"}, active_version="v1")


def test_secrets_config_validation_invalid_salt_type():
    """Testa erro quando salt não pode ser normalizado para bytes."""
    with pytest.raises(TypeError, match="Salt da versão 'v1' deve ser bytes"):
        SecretsConfig(keys={"v1": {"key": "k", "salt": 123}}, active_version="v1")


def test_secrets_config_from_environment(monkeypatch):
    """Testa criação de config a partir de variáveis de ambiente."""
    # Configurar ambiente
    monkeypatch.setenv("ENCRYPTION_KEYS__v1", "key1")
    monkeypatch.setenv("ENCRYPTION_SALT__v1", "salt1")
    monkeypatch.setenv("ACTIVE_ENCRYPTION_VERSION", "v1")

    config = SecretsConfig.from_environment()

    assert config.active_version == "v1"
    assert "v1" in config.keys
    assert config.keys["v1"]["key"] == "key1"
    assert config.keys["v1"]["salt"] == b"salt1"


def test_secrets_config_from_environment_skips_empty_key(monkeypatch):
    """Testa que chaves vazias são ignoradas."""
    monkeypatch.setenv("ENCRYPTION_KEYS__v1", "")
    monkeypatch.setenv("ENCRYPTION_SALT__v1", "salt1")
    monkeypatch.setenv("ENCRYPTION_KEYS__v2", "key2")
    monkeypatch.setenv("ENCRYPTION_SALT__v2", "salt2")
    monkeypatch.setenv("ACTIVE_ENCRYPTION_VERSION", "v2")

    config = SecretsConfig.from_environment()

    assert "v1" not in config.keys
    assert config.keys["v2"]["key"] == "key2"
    assert config.keys["v2"]["salt"] == b"salt2"


def test_secrets_config_from_environment_missing_salt(monkeypatch):
    """Testa erro quando salt está faltando no ambiente."""
    monkeypatch.setenv("ENCRYPTION_KEYS__v1", "key1")
    monkeypatch.setenv("ACTIVE_ENCRYPTION_VERSION", "v1")

    with pytest.raises(ValueError, match="Salt não encontrado"):
        SecretsConfig.from_environment()


def test_secrets_config_from_environment_no_keys(monkeypatch):
    """Testa erro quando não há chaves no ambiente."""
    # Limpar todas as variáveis de criptografia
    for key in list(monkeypatch._setitem):
        if "ENCRYPTION" in key:
            monkeypatch.delenv(key, raising=False)

    with pytest.raises(ValueError, match="Nenhuma chave de criptografia encontrada"):
        SecretsConfig.from_environment()


def test_secrets_config_from_environment_missing_active_version_with_multiple_keys(monkeypatch):
    """Testa erro quando há múltiplas versões e falta ACTIVE_ENCRYPTION_VERSION."""
    monkeypatch.setenv("ENCRYPTION_KEYS__v1", "key1")
    monkeypatch.setenv("ENCRYPTION_SALT__v1", "salt1")
    monkeypatch.setenv("ENCRYPTION_KEYS__v2", "key2")
    monkeypatch.setenv("ENCRYPTION_SALT__v2", "salt2")

    with pytest.raises(ValueError, match="Versão ativa não configurada"):
        SecretsConfig.from_environment()


def test_secrets_config_from_environment_single_key_defaults_active(monkeypatch):
    """Testa que a versão ativa padrão é usada quando há uma única chave."""
    monkeypatch.setenv("ENCRYPTION_KEYS__v1", "key1")
    monkeypatch.setenv("ENCRYPTION_SALT__v1", "salt1")

    config = SecretsConfig.from_environment()

    assert config.active_version == "v1"


def test_secrets_config_from_file(tmp_path):
    """Testa criação de config a partir de arquivo .env."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                'ENCRYPTION_KEYS__v1="key1"',
                'ENCRYPTION_SALT__v1="salt1"',
                'ACTIVE_ENCRYPTION_VERSION="v1"',
                "",
            ]
        )
    )

    config = SecretsConfig.from_file(str(env_file))

    assert config.active_version == "v1"
    assert "v1" in config.keys
    assert config.keys["v1"]["key"] == "key1"
    assert config.keys["v1"]["salt"] == b"salt1"


def test_secrets_config_from_file_missing_file(tmp_path):
    """Testa erro quando arquivo .env não existe."""
    missing = tmp_path / "missing.env"

    with pytest.raises(FileNotFoundError, match="Arquivo .env não encontrado"):
        SecretsConfig.from_file(str(missing))


def test_secrets_config_from_file_invalid_checksum(tmp_path):
    """Testa erro quando o checksum do arquivo .env é inválido."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                'ENCRYPTION_KEYS__v1="key1"',
                'ENCRYPTION_SALT__v1="salt1"',
                'ACTIVE_ENCRYPTION_VERSION="v1"',
                f'{ENV_CHECKSUM_KEY}="invalid"',
                "",
            ]
        )
    )

    with pytest.raises(ValueError, match="Checksum do arquivo .env inválido"):
        SecretsConfig.from_file(str(env_file))


def test_secrets_config_from_file_invalid_encoding(tmp_path):
    """Testa erro quando o arquivo .env tem encoding inválido."""
    env_file = tmp_path / ".env"
    env_file.write_bytes(b"\xff\xfe\xfa")

    with pytest.raises(UnicodeDecodeError):
        SecretsConfig.from_file(str(env_file))


def test_secrets_config_to_file_roundtrip(tmp_path):
    """Testa persistência de SecretsConfig em arquivo .env."""
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\n\nEXISTING_VAR=value\n")

    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    config.to_file(str(env_file), append=True)

    content = env_file.read_text()

    assert 'ENCRYPTION_KEYS__v1="k1"' in content
    assert 'ACTIVE_ENCRYPTION_VERSION="v1"' in content
    assert 'EXISTING_VAR="value"' in content
    assert "ENCRYPTION_SALT__v1" in content
    assert "ENCRYPTION_SALT_HASH__v1" in content
    assert ENV_CHECKSUM_KEY in content

    loaded = SecretsConfig.from_file(str(env_file))
    assert loaded.active_version == "v1"
    assert loaded.keys["v1"]["key"] == "k1"
    assert loaded.keys["v1"]["salt"] == b"s1"


def test_secrets_config_to_file_overwrite(tmp_path):
    """Testa que to_file sobrescreve por padrão."""
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_VAR=value\n")

    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    config.to_file(str(env_file))

    content = env_file.read_text()

    assert 'ENCRYPTION_KEYS__v1="k1"' in content
    assert "EXISTING_VAR" not in content
    assert ENV_CHECKSUM_KEY in content


def test_secrets_config_to_file_preserves_special_values(tmp_path):
    """Testa preservação de valores com # e aspas."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                'OTHER_VAR="value#123"',
                'OTHER_QUOTED="value\\"quoted"',
                "",
            ]
        )
    )

    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    config.to_file(str(env_file), append=True)

    content = env_file.read_text()
    assert 'OTHER_VAR="value#123"' in content
    assert 'OTHER_QUOTED="value\\"quoted"' in content


def test_secrets_config_to_file_read_only(monkeypatch):
    """Testa erro ao escrever arquivo sem permissão."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")

    def raise_permission(*args, **kwargs):
        raise PermissionError("read-only")

    monkeypatch.setattr("secrets_manager.config.locked_file", raise_permission)

    with pytest.raises(PermissionError, match="read-only"):
        config.to_file("readonly.env")


def test_secrets_config_to_file_disk_full(monkeypatch):
    """Testa erro ao escrever quando o disco está cheio."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")

    class DummyFile:
        def seek(self, *args, **kwargs):
            return None

        def truncate(self, *args, **kwargs):
            return None

        def write(self, *args, **kwargs):
            raise OSError(errno.ENOSPC, "No space left on device")

    @contextmanager
    def fake_locked_file(_path):
        yield DummyFile()

    monkeypatch.setattr("secrets_manager.config.locked_file", fake_locked_file)

    with pytest.raises(OSError, match="No space left on device"):
        config.to_file("full.env")
