"""Testes para o SecretsManager."""

import base64
import hashlib
import logging

import pytest

from secrets_manager import (
    KeyConfiguration,
    SecretsConfig,
    SecretsManager,
    SecretsManagerError,
    normalize_salt,
)


def test_normalize_salt():
    """Testa normalização de salt em vários formatos."""
    salt_bytes = b"salt123"
    salt_hex = salt_bytes.hex()
    salt_b64 = base64.urlsafe_b64encode(salt_bytes).decode("ascii")

    assert normalize_salt(salt_bytes) == salt_bytes
    assert normalize_salt(salt_hex) == salt_bytes
    assert normalize_salt(salt_b64) == salt_bytes
    assert normalize_salt("salt123") == salt_bytes  # UTF8 fallback

    with pytest.raises(TypeError):
        normalize_salt(123)


def test_key_configuration_integrity():
    """Testa validação de integridade do hash do salt."""
    salt = b"salt-integrity"
    salt_hash = hashlib.sha256(salt).hexdigest()

    # Hash correto - não deve levantar exceção
    config = KeyConfiguration(version="1", key=bytearray(b"k"), salt=salt, salt_hash=salt_hash)
    assert config.salt == salt

    # Hash incorreto - deve levantar exceção
    with pytest.raises(ValueError, match="Integridade do salt comprometida"):
        KeyConfiguration(version="1", key=bytearray(b"k"), salt=salt, salt_hash="hash-errado")


def test_secrets_config_validation():
    """Testa validação de SecretsConfig."""
    # Config válida
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": "s"}}, active_version="v1")
    assert config.active_version == "v1"

    # Config vazia
    with pytest.raises(ValueError, match="Pelo menos uma chave"):
        SecretsConfig(keys={}, active_version="v1")

    # Versão ativa inexistente
    with pytest.raises(ValueError, match="Versão ativa .* não existe"):
        SecretsConfig(keys={"v1": {"key": "k", "salt": "s"}}, active_version="v2")

    # Config incompleta (faltando salt)
    with pytest.raises(ValueError, match="deve conter 'key' e 'salt'"):
        SecretsConfig(keys={"v1": {"key": "k"}}, active_version="v1")


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
    assert config.keys["v1"]["salt"] == "salt1"


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


def test_secrets_manager_basic_encryption():
    """Testa criptografia/descriptografia básica."""
    config = SecretsConfig(keys={"v1": {"key": "pass", "salt": "salt"}}, active_version="v1")

    manager = SecretsManager(config)

    plaintext = b"sensitive data"
    version, ciphertext = manager.encrypt(plaintext)

    assert version == "v1"
    assert ciphertext != plaintext
    assert len(ciphertext) > len(plaintext)  # Overhead da criptografia

    # Decrypt
    version_used, decrypted = manager.decrypt(ciphertext)
    assert version_used == "v1"
    assert decrypted == plaintext


def test_secrets_manager_key_rotation():
    """Testa rotação de chaves."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": "s1"}}, active_version="v1")

    manager = SecretsManager(config)

    # Encrypt com v1
    _, ciphertext_v1 = manager.encrypt(b"data1")

    # Rotate para v2
    manager.rotate_to_new_version("v2", "k2", b"s2")

    # Verificar que v2 é agora ativa
    assert manager.get_active_version() == "v2"

    # Encrypt com v2
    version, ciphertext_v2 = manager.encrypt(b"data2")
    assert version == "v2"

    # Decrypt v1 ainda funciona (fallback automático)
    version_used, plaintext = manager.decrypt(ciphertext_v1)
    assert version_used == "v1"
    assert plaintext == b"data1"

    # Decrypt v2
    version_used, plaintext = manager.decrypt(ciphertext_v2)
    assert version_used == "v2"
    assert plaintext == b"data2"


def test_secrets_manager_decrypt_with_hint():
    """Testa decrypt com version_hint."""
    config = SecretsConfig(
        keys={"v1": {"key": "k1", "salt": "s1"}, "v2": {"key": "k2", "salt": "s2"}},
        active_version="v2",
    )

    manager = SecretsManager(config)

    # Encrypt com v1 (mudando temporariamente a versão ativa)
    manager.config.active_version = "v1"
    _, ciphertext_v1 = manager.encrypt(b"data")
    manager.config.active_version = "v2"

    # Decrypt com hint (mais eficiente)
    version_used, plaintext = manager.decrypt(ciphertext_v1, version_hint="v1")
    assert version_used == "v1"
    assert plaintext == b"data"


def test_secrets_manager_decrypt_all_versions_fail():
    """Testa erro quando decrypt falha com todas as versões."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": "s1"}}, active_version="v1")

    manager = SecretsManager(config)

    # Ciphertext inválido
    invalid_ciphertext = b"invalid data"

    with pytest.raises(SecretsManagerError, match="Falha ao descriptografar"):
        manager.decrypt(invalid_ciphertext)


def test_secrets_manager_statistics():
    """Testa estatísticas de uso."""
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": "s"}}, active_version="v1")

    manager = SecretsManager(config)

    # Operações
    _, ct1 = manager.encrypt(b"data1")
    _, ct2 = manager.encrypt(b"data2")
    manager.decrypt(ct1)

    stats = manager.get_statistics()

    assert stats["encryptions"] == 2
    assert stats["decryptions"] == 1
    assert stats["cache_hits"] >= 0
    assert stats["cache_misses"] >= 0


def test_secrets_manager_audit_callback():
    """Testa callback de auditoria."""
    audit_log = []

    def callback(event, metadata):
        audit_log.append((event, metadata))

    config = SecretsConfig(
        keys={"v1": {"key": "k", "salt": "s"}},
        active_version="v1",
        audit_callback=callback,
    )

    manager = SecretsManager(config)

    manager.encrypt(b"test data")

    assert len(audit_log) > 0
    assert audit_log[0][0] == "encryption"
    assert audit_log[0][1]["version"] == "v1"


def test_secrets_manager_persist_to_env_file(tmp_path):
    """Testa persistência em arquivo .env."""
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_VAR=value\n")

    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": "s1"}}, active_version="v1")

    manager = SecretsManager(config)

    # Rotacionar e persistir
    manager.rotate_to_new_version("v2", "k2", b"s2", persist_to_file=str(env_file))

    content = env_file.read_text()

    assert 'ENCRYPTION_KEYS__v2="k2"' in content
    assert 'ACTIVE_ENCRYPTION_VERSION="v2"' in content
    assert 'EXISTING_VAR="value"' in content  # Preserva existente
    assert "ENCRYPTION_SALT__v2" in content
    assert "ENCRYPTION_SALT_HASH__v2" in content


def test_secrets_manager_clear_cache():
    """Testa limpeza de cache."""
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": "s"}}, active_version="v1")

    manager = SecretsManager(config)

    # Preencher cache
    manager.get_fernet("v1")
    manager._load_key_config("v1")

    assert len(manager._fernet_cache) > 0
    assert len(manager._config_cache) > 0

    # Limpar
    manager.clear_cache()

    assert len(manager._fernet_cache) == 0
    assert len(manager._config_cache) == 0


def test_secrets_manager_custom_logger():
    """Testa uso de logger customizado."""
    # Criar logger mockado
    logger = logging.getLogger("test_logger")
    logger.setLevel(logging.DEBUG)

    config = SecretsConfig(
        keys={"v1": {"key": "k", "salt": "s"}}, active_version="v1", logger=logger
    )

    manager = SecretsManager(config)

    assert manager._logger == logger


def test_secrets_manager_get_all_versions():
    """Testa obtenção de todas as versões."""
    config = SecretsConfig(
        keys={
            "v1": {"key": "k1", "salt": "s1"},
            "v2": {"key": "k2", "salt": "s2"},
            "v3": {"key": "k3", "salt": "s3"},
        },
        active_version="v2",
    )

    manager = SecretsManager(config)

    versions = manager.get_all_versions()

    assert len(versions) == 3
    assert "v1" in versions
    assert "v2" in versions
    assert "v3" in versions


def test_secrets_manager_salt_integrity_validation():
    """Testa validação de integridade com verify_salt_integrity."""
    salt = b"salt-test"
    salt_hash = hashlib.sha256(salt).hexdigest()

    config = SecretsConfig(
        keys={"v1": {"key": "k", "salt": salt, "salt_hash": salt_hash}},
        active_version="v1",
        verify_salt_integrity=True,
    )

    manager = SecretsManager(config)

    # Deve carregar sem erro
    key_config = manager._load_key_config("v1")
    assert key_config.salt == salt


def test_secrets_manager_salt_integrity_disabled():
    """Testa que validação de integridade pode ser desabilitada."""
    salt = b"salt-test"

    config = SecretsConfig(
        keys={"v1": {"key": "k", "salt": salt, "salt_hash": "wrong-hash"}},
        active_version="v1",
        verify_salt_integrity=False,  # Desabilita validação
    )

    # Não deve levantar exceção mesmo com hash errado
    manager = SecretsManager(config)
    key_config = manager._load_key_config("v1")
    assert key_config.salt == salt


def test_secrets_manager_cleanup():
    """Testa limpeza segura de dados sensíveis da memória."""
    config = SecretsConfig(keys={"v1": {"key": "secret-key", "salt": "salt"}}, active_version="v1")
    manager = SecretsManager(config)

    # Carregar configs no cache
    manager._load_key_config("v1")

    assert len(manager._config_cache) > 0

    # Cleanup
    manager.cleanup()

    # Verificar que caches foram limpos
    assert len(manager._config_cache) == 0
    assert len(manager._fernet_cache) == 0


def test_key_configuration_cleanup():
    """Testa que cleanup sobrescreve a chave com zeros."""
    key = bytearray(b"sensitive-key-data")
    config = KeyConfiguration(version="v1", key=key, salt=b"salt")

    # Verificar que chave existe
    assert len(config.key) > 0
    assert config.key != bytearray(len(config.key))

    # Cleanup
    config.cleanup()

    # Verificar que foi zerada
    assert config.key == bytearray(len(config.key))


def test_atomic_counter_thread_safety():
    """Testa que AtomicCounter é thread-safe."""
    import threading

    from secrets_manager.manager import AtomicCounter

    counter = AtomicCounter()

    def increment_1000_times():
        for _ in range(1000):
            counter.increment()

    # 10 threads incrementando 1000 vezes cada
    threads = [threading.Thread(target=increment_1000_times) for _ in range(10)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Deve ser exatamente 10000 (sem race conditions)
    assert counter.value() == 10000


def test_secrets_manager_concurrent_statistics():
    """Testa que estatísticas são precisas sob operações concorrentes."""
    import threading

    config = SecretsConfig(keys={"v1": {"key": "k", "salt": "s"}}, active_version="v1")
    manager = SecretsManager(config)

    def encrypt_10_times():
        for _ in range(10):
            manager.encrypt(b"test data")

    # 5 threads criptografando 10 vezes cada
    threads = [threading.Thread(target=encrypt_10_times) for _ in range(5)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = manager.get_statistics()

    # Deve ser exatamente 50 sem perder nenhuma atualização
    assert stats["encryptions"] == 50
