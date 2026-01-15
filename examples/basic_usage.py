"""Exemplo básico de uso do Fernet Secrets Manager."""

import logging

from secrets_manager import SecretsConfig, SecretsManager

# Configurar logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Demonstra uso básico do SecretsManager."""

    print("\n=== Fernet Secrets Manager - Exemplo Básico ===\n")

    # 1. Criar configuração
    print("1. Criando configuração com uma versão de chave...")
    config = SecretsConfig(
        keys={
            "v1": {
                "key": "my-secret-password",
                "salt": b"random-salt-value",  # Em produção, use salt aleatório (bytes)
            }
        },
        active_version="v1",
        logger=logger,
    )
    print(f"   Versão ativa: {config.active_version}")

    # 2. Inicializar manager
    print("\n2. Inicializando SecretsManager...")
    manager = SecretsManager(config)
    print("   Manager inicializado com sucesso!")

    # 3. Criptografar dados
    print("\n3. Criptografando dados sensíveis...")
    plaintext = b"Informacao confidencial"
    version, ciphertext = manager.encrypt(plaintext)
    print(f"   Versão usada: {version}")
    print(f"   Plaintext:  {plaintext}")
    print(f"   Ciphertext: {ciphertext[:50]}...")  # Mostra apenas primeiros 50 bytes

    # 4. Descriptografar dados
    print("\n4. Descriptografando dados...")
    version_used, decrypted = manager.decrypt(ciphertext)
    print(f"   Versão usada: {version_used}")
    print(f"   Decrypted: {decrypted}")
    print(f"   ✓ Dados recuperados com sucesso!")

    # 5. Validar que decrypted == plaintext
    assert decrypted == plaintext, "Erro: dados descriptografados não conferem!"

    # 6. Múltiplas operações
    print("\n5. Realizando múltiplas operações...")
    data_list = [
        b"Usuario: john@example.com",
        b"Senha: super-secret-123",
        b"API Key: sk-1234567890",
    ]

    encrypted_data = []
    for data in data_list:
        _, ct = manager.encrypt(data)
        encrypted_data.append(ct)
        print(f"   ✓ Criptografado: {data.decode()[:30]}...")

    # 7. Descriptografar tudo
    print("\n6. Descriptografando todos os dados...")
    for ct in encrypted_data:
        _, pt = manager.decrypt(ct)
        print(f"   ✓ Recuperado: {pt.decode()[:30]}...")

    # 8. Estatísticas
    print("\n7. Estatísticas de uso:")
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    # 9. Listar todas as versões
    print("\n8. Versões disponíveis:")
    versions = manager.get_all_versions()
    for v in versions:
        print(f"   - {v}")

    # 10. Limpar material criptográfico sensível
    print("\n9. Limpando material sensível da memória...")
    manager.cleanup()
    print("   ✓ Limpeza de segurança concluída")

    print("\n=== Fim do exemplo ===\n")


if __name__ == "__main__":
    main()
