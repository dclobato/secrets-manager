"""Configurações e dataclasses para o SecretsManager."""

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Self


@dataclass(frozen=True)
class KeyConfiguration:
    """Configuração imutável e validada de uma versão de chave.

    NOTA DE SEGURANÇA: Esta classe usa bytearray ao invés de str para a chave criptográfica
    para permitir limpeza segura de memória. Diferente de str (que é imutável em Python),
    bytearray é mutável e pode ser zerado quando não for mais necessário, reduzindo a
    janela onde material de chave sensível permanece na memória.

    Embora o coletor de lixo do Python ainda possa deixar cópias na memória (devido a
    internação de strings, contagem de referências, etc.), usar bytearray fornece segurança
    de melhor esforço ao permitir limpeza explícita via método cleanup().

    Attributes:
        version: Nome da versão (e.g., "v1", "v2")
        key: Chave de criptografia como bytearray (será derivada com PBKDF2)
        salt: Salt para derivação (bytes)
        salt_hash: Hash SHA256 do salt para validação de integridade (opcional)
    """

    version: str
    key: bytearray
    salt: bytes
    salt_hash: Optional[str] = None

    def __post_init__(self) -> None:
        """Valida integridade após inicialização."""
        if self.salt_hash:
            computed = hashlib.sha256(self.salt).hexdigest()
            if computed != self.salt_hash:
                raise ValueError(
                    f"Integridade do salt comprometida para versão {self.version}. "
                    f"Hash esperado: {self.salt_hash}, calculado: {computed}"
                )

    def cleanup(self) -> None:
        """Zera de forma segura a chave de criptografia na memória.

        NOTA DE SEGURANÇA: Este método sobrescreve o bytearray da chave com zeros
        para minimizar o tempo que material criptográfico sensível permanece na memória.

        Chame este método quando:
        - A aplicação estiver sendo encerrada
        - Após rotação de chaves (para chaves antigas)
        - Quando a chave não for mais necessária

        IMPORTANTE: Esta é segurança de melhor esforço em Python. Devido a:
        - Contagem de referências e coletor de lixo do Python
        - Potencial internação de strings durante criação do bytearray
        - Otimizações do gerenciador de memória
        - Gerenciamento de memória do sistema operacional

        Não há garantia de que todas as cópias do material de chave sejam removidas
        da memória. No entanto, isto reduz significativamente a superfície de ataque
        comparado ao uso de objetos str imutáveis.

        Após chamar cleanup(), esta instância KeyConfiguration não deve ser usada.
        """
        # Zera o bytearray no local
        # Nota: bytearray é mutável, então podemos modificar seu conteúdo mesmo
        # em um dataclass frozen. O atributo frozen apenas previne reatribuir a
        # referência, não modificar o objeto
        if self.key:
            for i in range(len(self.key)):
                self.key[i] = 0


@dataclass
class SecretsConfig:
    """Configuração do SecretsManager.

    Attributes:
        keys: Dicionário de versões e suas configurações
              Formato: {version: {key, salt, salt_hash?}}
        active_version: Versão ativa para novas criptografias
        kdf_iterations: Número de iterações PBKDF2 (padrão: 100_000)
        verify_salt_integrity: Se deve validar hash do salt (padrão: True)
        audit_callback: Callback opcional para auditoria de eventos
        logger: Logger opcional para mensagens (usa logging padrão se None)
    """

    keys: Dict[str, Dict[str, Any]]
    active_version: str
    kdf_iterations: int = 100_000
    verify_salt_integrity: bool = True
    audit_callback: Optional[Callable] = None
    logger: Optional[Any] = None  # logging.Logger

    def __post_init__(self) -> None:
        """Valida configuração após inicialização."""
        if not self.keys:
            raise ValueError("Pelo menos uma chave deve ser configurada")

        if self.active_version not in self.keys:
            raise ValueError(
                f"Versão ativa '{self.active_version}' não existe nas chaves configuradas. "
                f"Versões disponíveis: {list(self.keys.keys())}"
            )

        # Valida que todas as chaves têm os campos necessários
        for version, config in self.keys.items():
            if not isinstance(config, dict):
                raise ValueError(f"Configuração da versão '{version}' deve ser um dicionário")
            if "key" not in config or "salt" not in config:
                raise ValueError(f"Configuração da versão '{version}' deve conter 'key' e 'salt'")

    @classmethod
    def from_environment(
        cls,
        keys_prefix: str = "ENCRYPTION_KEYS",
        salt_prefix: str = "ENCRYPTION_SALT",
        salt_hash_prefix: str = "ENCRYPTION_SALT_HASH",
        active_version_key: str = "ACTIVE_ENCRYPTION_VERSION",
        **kwargs: Any,
    ) -> Self:
        """Cria configuração a partir de variáveis de ambiente.

        Formato esperado:
            ENCRYPTION_KEYS__v1=my-key
            ENCRYPTION_SALT__v1=my-salt
            ENCRYPTION_SALT_HASH__v1=sha256-hash (opcional)
            ACTIVE_ENCRYPTION_VERSION=v1

        Args:
            keys_prefix: Prefixo para chaves (padrão: ENCRYPTION_KEYS)
            salt_prefix: Prefixo para salts (padrão: ENCRYPTION_SALT)
            salt_hash_prefix: Prefixo para hashes (padrão: ENCRYPTION_SALT_HASH)
            active_version_key: Chave para versão ativa (padrão: ACTIVE_ENCRYPTION_VERSION)
            **kwargs: Argumentos adicionais para SecretsConfig

        Returns:
            SecretsConfig configurado a partir do ambiente

        Raises:
            ValueError: Se configuração for inválida ou incompleta
        """
        keys: Dict[str, Dict[str, Any]] = {}

        # Encontrar todas as versões configuradas
        for env_key in os.environ:
            if env_key.startswith(f"{keys_prefix}__"):
                version = env_key.split("__", 1)[1].lower()

                # Buscar chave
                key_value = os.environ.get(env_key)
                if not key_value:
                    continue

                # Buscar salt (case-insensitive)
                salt_key = f"{salt_prefix}__{version}"
                salt_value = None
                for k in os.environ:
                    if k.upper() == salt_key.upper():
                        salt_value = os.environ[k]
                        break

                if not salt_value:
                    raise ValueError(
                        f"Salt não encontrado para versão '{version}'. " f"Esperado: {salt_key}"
                    )

                # Buscar hash (opcional)
                hash_key = f"{salt_hash_prefix}__{version}"
                hash_value = None
                for k in os.environ:
                    if k.upper() == hash_key.upper():
                        hash_value = os.environ[k]
                        break

                keys[version] = {
                    "key": key_value,
                    "salt": salt_value,
                    "salt_hash": hash_value,
                }

        if not keys:
            raise ValueError(
                f"Nenhuma chave de criptografia encontrada no ambiente. "
                f"Formato esperado: {keys_prefix}__<version>=<key>"
            )

        # Buscar versão ativa
        active_version = os.environ.get(active_version_key)
        if not active_version:
            # Se houver apenas uma versão, usa-a
            if len(keys) == 1:
                active_version = next(iter(keys.keys()))
            else:
                raise ValueError(
                    f"Versão ativa não configurada ({active_version_key}) "
                    f"e há múltiplas versões disponíveis"
                )

        # Remover aspas (problema comum com dotenv)
        active_version = active_version.strip("\"'").lower()

        return cls(keys=keys, active_version=active_version, **kwargs)
