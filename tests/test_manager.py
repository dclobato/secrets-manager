"""Testes para SecretsManager."""

import hashlib
import logging

import pytest

from secrets_manager import SecretsConfig, SecretsManager, SecretsManagerError
from secrets_manager.utils import ENV_CHECKSUM_KEY


def test_secrets_manager_basic_encryption():
    """Testa criptografia/descriptografia básica."""
    config = SecretsConfig(keys={"v1": {"key": "pass", "salt": b"salt"}}, active_version="v1")

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
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")

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
        keys={"v1": {"key": "k1", "salt": b"s1"}, "v2": {"key": "k2", "salt": b"s2"}},
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
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")

    manager = SecretsManager(config)

    # Ciphertext inválido
    invalid_ciphertext = b"invalid data"

    with pytest.raises(SecretsManagerError, match="Falha ao descriptografar"):
        manager.decrypt(invalid_ciphertext)


def test_secrets_manager_statistics():
    """Testa estatísticas de uso."""
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": b"s"}}, active_version="v1")

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
        keys={"v1": {"key": "k", "salt": b"s"}},
        active_version="v1",
        audit_callback=callback,
    )

    manager = SecretsManager(config)

    manager.encrypt(b"test data")

    assert len(audit_log) > 0
    assert audit_log[0][0] == "encryption"
    assert audit_log[0][1]["version"] == "v1"


def test_secrets_manager_audit_callback_exception(caplog):
    """Testa que exceções no callback de auditoria são tratadas."""
    def callback(event, metadata):
        raise RuntimeError("audit fail")

    config = SecretsConfig(
        keys={"v1": {"key": "k", "salt": b"s"}},
        active_version="v1",
        audit_callback=callback,
    )

    caplog.set_level(logging.WARNING)
    manager = SecretsManager(config)
    manager.encrypt(b"data")

    assert "Erro no callback de auditoria" in caplog.text


def test_secrets_manager_persist_to_env_file(tmp_path):
    """Testa persistência em arquivo .env."""
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_VAR=value\n")

    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")

    manager = SecretsManager(config)

    # Rotacionar e persistir
    manager.rotate_to_new_version("v2", "k2", b"s2", persist_to_file=str(env_file))

    content = env_file.read_text()

    assert 'ENCRYPTION_KEYS__v2="k2"' in content
    assert 'ACTIVE_ENCRYPTION_VERSION="v2"' in content
    assert 'EXISTING_VAR="value"' in content  # Preserva existente
    assert "ENCRYPTION_SALT__v2" in content
    assert "ENCRYPTION_SALT_HASH__v2" in content
    assert ENV_CHECKSUM_KEY in content


def test_secrets_manager_persist_to_env_file_skips_comments(tmp_path):
    """Testa que comentários e linhas vazias são ignorados na persistência."""
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\n\nEXISTING_VAR=value\n")

    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    manager = SecretsManager(config)

    manager.rotate_to_new_version("v2", "k2", b"s2", persist_to_file=str(env_file))

    content = env_file.read_text()
    assert 'EXISTING_VAR="value"' in content
    assert "comment" not in content


def test_secrets_manager_clear_cache():
    """Testa limpeza de cache."""
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": b"s"}}, active_version="v1")

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
        keys={"v1": {"key": "k", "salt": b"s"}}, active_version="v1", logger=logger
    )

    manager = SecretsManager(config)

    assert manager._logger == logger


def test_secrets_manager_validate_configuration_no_keys():
    """Testa erro quando não há chaves configuradas."""
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": b"s"}}, active_version="v1")
    config.keys = {}

    with pytest.raises(SecretsManagerError, match="Nenhuma chave de criptografia configurada"):
        SecretsManager(config)


def test_secrets_manager_validate_configuration_active_version_missing():
    """Testa erro quando a versão ativa não existe nas chaves."""
    config = SecretsConfig(keys={"v1": {"key": "k", "salt": b"s"}}, active_version="v1")
    config.active_version = "v2"

    with pytest.raises(SecretsManagerError, match="Versão ativa 'v2' não existe"):
        SecretsManager(config)


def test_secrets_manager_get_all_versions():
    """Testa obtenção de todas as versões."""
    config = SecretsConfig(
        keys={
            "v1": {"key": "k1", "salt": b"s1"},
            "v2": {"key": "k2", "salt": b"s2"},
            "v3": {"key": "k3", "salt": b"s3"},
        },
        active_version="v2",
    )

    manager = SecretsManager(config)

    versions = manager.get_all_versions()

    assert len(versions) == 3
    assert "v1" in versions
    assert "v2" in versions
    assert "v3" in versions


def test_secrets_manager_load_key_config_missing_version():
    """Testa erro quando a versão não existe."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    manager = SecretsManager(config)

    with pytest.raises(SecretsManagerError, match="Versão 'v2' não encontrada"):
        manager._load_key_config("v2")


def test_secrets_manager_load_key_config_invalid_format():
    """Testa erro quando a configuração da versão é inválida."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    manager = SecretsManager(config)

    manager.config.keys["v1"] = "invalid"
    manager.clear_cache()

    with pytest.raises(SecretsManagerError, match="Configuração inválida"):
        manager._load_key_config("v1")


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


def test_secrets_manager_rotate_without_existing_salt():
    """Testa erro quando não há salt existente e new_salt é None."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    manager = SecretsManager(config)

    manager.config.keys = {}
    manager.clear_cache()

    with pytest.raises(SecretsManagerError, match="Nenhuma configuração existente"):
        manager.rotate_to_new_version("v2", "k2", None)


def test_secrets_manager_rotate_reuses_existing_salt():
    """Testa que rotate reutiliza o salt existente quando new_salt é None."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    manager = SecretsManager(config)

    manager.rotate_to_new_version("v2", "k2", None)

    assert manager.config.keys["v2"]["salt"] == b"s1"


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


def test_atomic_counter_thread_safety():
    """Testa que AtomicCounter é thread-safe."""
    import threading

    from secrets_manager.manager import AtomicCounter

    counter = AtomicCounter()
    num_threads = 10
    increments_per_thread = 100

    def increment_counter():
        for _ in range(increments_per_thread):
            counter.increment()

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=increment_counter)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Se o contador fosse não thread-safe, poderíamos perder updates
    # Com thread-safety, deve ser exatamente num_threads * increments_per_thread
    assert counter.value() == num_threads * increments_per_thread


def test_atomic_counter_basic():
    """Testa operações básicas do AtomicCounter."""
    from secrets_manager.manager import AtomicCounter

    counter = AtomicCounter()
    assert counter.value() == 0

    counter.increment()
    assert counter.value() == 1

    counter.increment()
    counter.increment()
    assert counter.value() == 3


def test_key_configuration_cleanup():
    """Testa que KeyConfiguration.cleanup() zera a chave."""
    from secrets_manager import KeyConfiguration

    key_str = "my-secret-key"
    key_bytearray = bytearray(key_str.encode("utf-8"))

    config = KeyConfiguration(
        version="v1",
        key=key_bytearray,
        salt=b"salt123",
    )

    # Verificar que a chave está presente antes do cleanup
    assert len(config.key) == len(key_str)
    assert bytes(config.key) == key_str.encode("utf-8")

    # Chamar cleanup
    config.cleanup()

    # Verificar que a chave foi zerada
    assert all(b == 0 for b in config.key)
    assert bytes(config.key) == b"\x00" * len(key_str)


def test_secrets_manager_cleanup():
    """Testa que SecretsManager.cleanup() limpa todas as chaves."""
    config = SecretsConfig(
        keys={
            "v1": {"key": "key1", "salt": b"salt1"},
            "v2": {"key": "key2", "salt": b"salt2"},
        },
        active_version="v1",
    )

    manager = SecretsManager(config)

    # Carregar configs para popular cache
    key_config_v1 = manager._load_key_config("v1")
    key_config_v2 = manager._load_key_config("v2")

    # Verificar que as chaves estão no cache
    assert len(manager._config_cache) == 2

    # Verificar que as chaves não estão zeradas
    assert not all(b == 0 for b in key_config_v1.key)
    assert not all(b == 0 for b in key_config_v2.key)

    # Chamar cleanup
    manager.cleanup()

    # Verificar que os caches foram limpos
    assert len(manager._config_cache) == 0
    assert len(manager._fernet_cache) == 0

    # Verificar que as chaves foram zeradas (nas instâncias originais)
    assert all(b == 0 for b in key_config_v1.key)
    assert all(b == 0 for b in key_config_v2.key)


def test_secrets_manager_cleanup_handles_errors(caplog):
    """Testa que cleanup trata exceções ao limpar chaves."""
    config = SecretsConfig(keys={"v1": {"key": "k1", "salt": b"s1"}}, active_version="v1")
    caplog.set_level(logging.WARNING)
    manager = SecretsManager(config)

    class BadKeyConfig:
        version = "v1"

        def cleanup(self):
            raise RuntimeError("cleanup fail")

    manager._config_cache["v1"] = BadKeyConfig()
    manager.cleanup()

    assert "Erro ao limpar configuração de chave para versão v1" in caplog.text


def test_secrets_manager_bytearray_key_usage():
    """Testa que chaves são armazenadas como bytearray."""
    config = SecretsConfig(
        keys={"v1": {"key": "test-key", "salt": b"test-salt"}},
        active_version="v1",
    )

    manager = SecretsManager(config)
    key_config = manager._load_key_config("v1")

    # Verificar que a chave é bytearray
    assert isinstance(key_config.key, bytearray)

    # Verificar que criptografia/descriptografia ainda funcionam
    plaintext = b"test data"
    version, ciphertext = manager.encrypt(plaintext)
    _, decrypted = manager.decrypt(ciphertext)
    assert decrypted == plaintext
