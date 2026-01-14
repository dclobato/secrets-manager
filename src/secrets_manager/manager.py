"""SecretsManager - Gerenciador de segredos com rotação de chaves."""

import base64
import gc
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, RLock
from typing import Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import KeyConfiguration, SecretsConfig
from .utils import normalize_salt, normalize_version


class AtomicCounter:
    """Thread-safe counter for statistics tracking.

    Uses a lock to ensure atomic increment and read operations,
    preventing race conditions under concurrent access.
    """

    def __init__(self) -> None:
        """Initialize counter with zero value."""
        self._value = 0
        self._lock = Lock()

    def increment(self) -> None:
        """Atomically increment the counter by 1."""
        with self._lock:
            self._value += 1

    def value(self) -> int:
        """Atomically read the current counter value.

        Returns:
            int: Current counter value
        """
        with self._lock:
            return self._value


class SecretsManagerError(Exception):
    """Erro específico do gerenciador de segredos."""

    pass


class SecretsManager:
    """Gerenciador de segredos com criptografia Fernet e rotação de chaves.

    Esta classe fornece:
    - Criptografia/descriptografia segura com Fernet
    - Rotação de chaves multi-versão
    - Derivação de chaves com PBKDF2
    - Cache thread-safe de instâncias Fernet
    - Auditoria configurável via callbacks
    - Estatísticas de uso

    Attributes:
        config: Configuração do gerenciador
    """

    def __init__(self, config: SecretsConfig):
        """Inicializa o SecretsManager.

        Args:
            config: Configuração do gerenciador
        """
        self.config = config
        self._logger = config.logger or logging.getLogger(__name__)

        # Caches thread-safe
        self._config_cache: Dict[str, KeyConfiguration] = {}
        self._fernet_cache: Dict[str, Fernet] = {}
        self._lock = RLock()

        # Estatísticas (thread-safe atomic counters)
        self._stats = {
            "encryptions": AtomicCounter(),
            "decryptions": AtomicCounter(),
            "cache_hits": AtomicCounter(),
            "cache_misses": AtomicCounter(),
            "integrity_checks": AtomicCounter(),
        }

        # Valida configuração
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """Valida que a configuração está correta."""
        # Tenta carregar todas as configurações
        configs = self._load_all_key_configs()
        if not configs:
            raise SecretsManagerError("Nenhuma chave de criptografia configurada")

        active = self.get_active_version()
        if active not in configs:
            raise SecretsManagerError(
                f"Versão ativa '{active}' não existe nas chaves configuradas. "
                f"Versões disponíveis: {list(configs.keys())}"
            )

        self._logger.info("Configuração de criptografia validada com sucesso")

    def _load_key_config(self, version: str) -> KeyConfiguration:
        """Carrega e valida configuração de uma versão específica.

        Args:
            version: Versão da chave a carregar

        Returns:
            KeyConfiguration validada

        Raises:
            SecretsManagerError: Se versão não existir ou configuração for inválida
        """
        # Normalizar versão
        version = normalize_version(version)

        # Cache check
        with self._lock:
            if version in self._config_cache:
                self._stats["cache_hits"].increment()
                return self._config_cache[version]

        self._stats["cache_misses"].increment()

        # Normalizar chaves do dicionário
        normalized_keys = {normalize_version(k): v for k, v in self.config.keys.items()}

        if version not in normalized_keys:
            raise SecretsManagerError(
                f"Versão '{version}' não encontrada. "
                f"Versões disponíveis: {list(normalized_keys.keys())}"
            )

        config_dict = normalized_keys[version]

        # Validar formato
        if (
            not isinstance(config_dict, dict)
            or "key" not in config_dict
            or "salt" not in config_dict
        ):
            raise SecretsManagerError(
                f"Configuração inválida para versão '{version}'. "
                f"Esperado: {{'key': '...', 'salt': '...'}}"
            )

        # Normalizar salt
        salt_bytes = normalize_salt(config_dict["salt"])

        # Hash do salt (se verificação habilitada)
        salt_hash = config_dict.get("salt_hash") if self.config.verify_salt_integrity else None

        if salt_hash:
            self._stats["integrity_checks"].increment()

        # Criar configuração
        # Convert string key to bytearray for secure memory management
        key_str = config_dict["key"]
        key_bytearray = bytearray(key_str.encode("utf-8"))

        key_config = KeyConfiguration(
            version=version,
            key=key_bytearray,
            salt=salt_bytes,
            salt_hash=salt_hash,
        )

        # Cache
        with self._lock:
            self._config_cache[version] = key_config

        return key_config

    def _load_all_key_configs(self) -> Dict[str, KeyConfiguration]:
        """Carrega todas as configurações de chaves disponíveis.

        Returns:
            Dict mapeando versão para KeyConfiguration
        """
        result = {}

        # Normalizar chaves para lowercase
        normalized_keys = {normalize_version(k): v for k, v in self.config.keys.items()}

        # Carregar cada config
        for version in normalized_keys.keys():
            result[version] = self._load_key_config(version)

        return result

    def _derive_fernet(self, key_config: KeyConfiguration) -> Fernet:
        """Deriva chave Fernet usando PBKDF2.

        Args:
            key_config: Configuração da chave

        Returns:
            Instância Fernet derivada
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_config.salt,
            iterations=self.config.kdf_iterations,
        )
        # Convert bytearray to bytes for PBKDF2
        key_bytes = bytes(key_config.key)
        derived = kdf.derive(key_bytes)
        fernet_key = base64.urlsafe_b64encode(derived)
        return Fernet(fernet_key)

    def get_active_version(self) -> str:
        """Retorna a versão de chave ativa (normalizada).

        Returns:
            str: Versão ativa em lowercase
        """
        version = self.config.active_version.strip("\"'")
        return normalize_version(version)

    def get_fernet(self, version: str) -> Fernet:
        """Obtém uma instância Fernet para a versão especificada.

        Usa cache para otimização.

        Args:
            version: Versão da chave

        Returns:
            Instância Fernet derivada

        Raises:
            SecretsManagerError: Se versão não for encontrada
        """
        # Normalizar versão
        version = normalize_version(version)

        # Cache key inclui iterações (para suportar mudança de config)
        cache_key = f"{version}:{self.config.kdf_iterations}"

        # Cache check
        with self._lock:
            if cache_key in self._fernet_cache:
                return self._fernet_cache[cache_key]

        # Derivar
        key_config = self._load_key_config(version)
        fernet = self._derive_fernet(key_config)

        # Cache
        with self._lock:
            self._fernet_cache[cache_key] = fernet

        return fernet

    def get_all_versions(self) -> List[str]:
        """Retorna lista de todas as versões disponíveis.

        Returns:
            List[str]: Lista de versões normalizadas
        """
        return list(self._load_all_key_configs().keys())

    def encrypt(self, plaintext: bytes) -> Tuple[str, bytes]:
        """Criptografa dados usando a versão ativa.

        Args:
            plaintext: Dados em texto plano (bytes)

        Returns:
            Tuple[str, bytes]: (versão usada, ciphertext)

        Examples:
            >>> version, ciphertext = manager.encrypt(b"sensitive data")
            >>> print(f"Encrypted with: {version}")
        """
        version = self.get_active_version()
        fernet = self.get_fernet(version)
        ciphertext = fernet.encrypt(plaintext)

        self._stats["encryptions"].increment()
        self._audit("encryption", {"version": version, "size": len(plaintext)})

        return version, ciphertext

    def decrypt(self, ciphertext: bytes, version_hint: Optional[str] = None) -> Tuple[str, bytes]:
        """Descriptografa dados, tentando múltiplas versões automaticamente.

        Ordem de tentativa:
        1. version_hint (se fornecido)
        2. Versão ativa
        3. Todas as outras versões

        Args:
            ciphertext: Dados criptografados
            version_hint: Dica de versão a tentar primeiro (opcional)

        Returns:
            Tuple[str, bytes]: (versão usada, plaintext)

        Raises:
            SecretsManagerError: Se falhar com todas as versões

        Examples:
            >>> version, plaintext = manager.decrypt(ciphertext)
            >>> print(f"Decrypted with: {version}")

            >>> # Com hint
            >>> version, plaintext = manager.decrypt(ciphertext, version_hint="v1")
        """
        versions_to_try = []

        # Ordem: hint, ativa, todas as outras
        if version_hint:
            versions_to_try.append(normalize_version(version_hint))

        active = self.get_active_version()
        if active not in versions_to_try:
            versions_to_try.append(active)

        for v in self.get_all_versions():
            if v not in versions_to_try:
                versions_to_try.append(v)

        last_error = None
        for version in versions_to_try:
            try:
                fernet = self.get_fernet(version)
                plaintext = fernet.decrypt(ciphertext)

                self._stats["decryptions"].increment()
                self._audit("decryption", {"version": version, "was_hint": version == version_hint})

                return version, plaintext
            except InvalidToken as e:
                last_error = e
                continue

        raise SecretsManagerError(
            f"Falha ao descriptografar com todas as versões tentadas. " f"Último erro: {last_error}"
        )

    def rotate_to_new_version(
        self,
        new_version: str,
        new_key: str,
        new_salt: Optional[bytes] = None,
        persist_to_file: Optional[str] = None,
    ) -> None:
        """Adiciona nova versão e a marca como ativa.

        Args:
            new_version: Nome da nova versão (e.g., "v2")
            new_key: Chave de criptografia
            new_salt: Salt (se None, reutiliza salt existente)
            persist_to_file: Caminho do arquivo .env para persistir (opcional)

        Raises:
            SecretsManagerError: Se salt não puder ser determinado

        Examples:
            >>> manager.rotate_to_new_version("v2", "new-key", b"new-salt")
            >>> # Nova versão agora está ativa para novas criptografias
        """
        # Reutilizar salt se não fornecido
        if new_salt is None:
            existing_configs = self._load_all_key_configs()
            if existing_configs:
                first_config = next(iter(existing_configs.values()))
                new_salt = first_config.salt
            else:
                raise SecretsManagerError(
                    "Nenhuma configuração existente para reutilizar salt. "
                    "Forneça new_salt explicitamente."
                )

        # Atualizar configuração em memória
        new_version_normalized = normalize_version(new_version)

        self.config.keys[new_version_normalized] = {
            "key": new_key,
            "salt": base64.urlsafe_b64encode(new_salt).decode("ascii"),
        }
        self.config.active_version = new_version_normalized

        # Limpar caches
        with self._lock:
            self._config_cache.clear()
            self._fernet_cache.clear()

        # Persistir se solicitado
        if persist_to_file:
            self._persist_to_env_file(persist_to_file, new_version_normalized, new_key, new_salt)

        self._audit("rotation", {"new_version": new_version_normalized})

        self._logger.info(f"Rotação completa para versão: {new_version_normalized}")

    def _persist_to_env_file(self, filename: str, version: str, key: str, salt: bytes) -> None:
        """Atualiza arquivo .env mantendo outras variáveis.

        Args:
            filename: Caminho do arquivo .env
            version: Versão da chave
            key: Chave de criptografia
            salt: Salt (bytes)
        """
        data = {}
        env_path = Path(filename)

        # Ler arquivo existente
        if env_path.exists():
            with env_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        data[k.strip()] = v.strip().strip('"').strip("'")

        # Adicionar/atualizar nova versão
        data[f"ENCRYPTION_KEYS__{version}"] = key
        data[f"ENCRYPTION_SALT__{version}"] = base64.urlsafe_b64encode(salt).decode("ascii")
        data["ACTIVE_ENCRYPTION_VERSION"] = version

        # Calcular hash do salt para integridade
        salt_hash = hashlib.sha256(salt).hexdigest()
        data[f"ENCRYPTION_SALT_HASH__{version}"] = salt_hash

        # Escrever de volta
        with env_path.open("w", encoding="utf-8") as f:
            f.write(f"# Atualizado em {datetime.now(timezone.utc).isoformat()}\n")
            for k, v in sorted(data.items()):
                f.write(f'{k}="{v}"\n')

        self._logger.info(f"Configuração persistida em: {filename}")

    def _audit(self, event: str, metadata: dict) -> None:
        """Registra evento de auditoria se callback configurado.

        Args:
            event: Nome do evento (e.g., "encryption", "decryption", "rotation")
            metadata: Metadados do evento
        """
        if self.config.audit_callback:
            try:
                self.config.audit_callback(event, metadata)
            except Exception as e:
                self._logger.warning(f"Erro no callback de auditoria: {e}")

    def get_statistics(self) -> dict:
        """Retorna estatísticas de uso.

        Returns:
            dict: Estatísticas com contadores de operações

        Examples:
            >>> stats = manager.get_statistics()
            >>> print(f"Encryptions: {stats['encryptions']}")
        """
        return {
            "encryptions": self._stats["encryptions"].value(),
            "decryptions": self._stats["decryptions"].value(),
            "cache_hits": self._stats["cache_hits"].value(),
            "cache_misses": self._stats["cache_misses"].value(),
            "integrity_checks": self._stats["integrity_checks"].value(),
        }

    def clear_cache(self) -> None:
        """Limpa todos os caches.

        Útil para testes ou após mudança de configuração.
        """
        with self._lock:
            self._config_cache.clear()
            self._fernet_cache.clear()

        self._logger.debug("Caches limpos")

    def cleanup(self) -> None:
        """Securely clear sensitive data from memory.

        SECURITY: This method performs the following cleanup operations:
        1. Calls cleanup() on all cached KeyConfiguration instances to zero keys
        2. Clears all caches (config and Fernet instances)
        3. Forces garbage collection to reclaim memory

        WHY THIS MATTERS:
        - Minimizes the window of exposure for cryptographic keys in memory
        - Reduces risk of key exposure in memory dumps or swap files
        - Best practice before shutdown or after key rotation

        PYTHON GC LIMITATIONS:
        - Python's garbage collector may leave copies of data in memory
        - This is "best-effort" security, not a guarantee
        - However, it significantly reduces the attack surface

        WHEN TO CALL:
        - Before shutting down your application
        - After key rotation in high-security environments
        - When disposing of SecretsManager instances
        - In finally blocks or context manager __exit__ methods

        Example:
            >>> manager = SecretsManager(config)
            >>> try:
            ...     # Use manager
            ...     manager.encrypt(b"data")
            >>> finally:
            ...     manager.cleanup()
        """
        with self._lock:
            # Securely zero all cached keys
            for key_config in self._config_cache.values():
                key_config.cleanup()

            # Clear all caches
            self._config_cache.clear()
            self._fernet_cache.clear()

        # Force garbage collection to reclaim memory
        gc.collect()

        self._logger.info("Sensitive data securely cleared from memory")
