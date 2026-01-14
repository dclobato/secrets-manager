"""Exemplo de rotação de chaves com Fernet Secrets Manager."""

import logging
import os
from pathlib import Path

from secrets_manager import SecretsConfig, SecretsManager

# Configurar logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Demonstra rotação de chaves."""

    print("\n=== Fernet Secrets Manager - Rotação de Chaves ===\n")

    # 1. Configuração inicial com v1
    print("1. Configuração inicial com versão v1...")
    config = SecretsConfig(
        keys={"v1": {"key": "old-password", "salt": "old-salt"}},
        active_version="v1",
        logger=logger,
    )

    manager = SecretsManager(config)
    print(f"   Versão ativa: {manager.get_active_version()}")

    # 2. Criptografar dados com v1
    print("\n2. Criptografando dados com v1...")
    data_v1 = [
        b"Documento antigo 1",
        b"Documento antigo 2",
        b"Documento antigo 3",
    ]

    ciphertexts_v1 = []
    for data in data_v1:
        version, ct = manager.encrypt(data)
        ciphertexts_v1.append((version, ct))
        print(f"   ✓ Criptografado com {version}: {data.decode()}")

    # 3. Simular necessidade de rotação (ex: chave comprometida, política de segurança)
    print("\n3. Necessidade de rotação detectada!")
    print("   Motivos possíveis:")
    print("   - Chave pode ter sido comprometida")
    print("   - Política de rotação periódica (ex: 90 dias)")
    print("   - Upgrade de algoritmo ou parâmetros")

    # 4. Rotacionar para v2
    print("\n4. Rotacionando para versão v2...")
    manager.rotate_to_new_version(
        new_version="v2",
        new_key="new-stronger-password",
        new_salt=b"new-random-salt",  # Em produção, use os.urandom(16)
    )
    print(f"   ✓ Versão ativa agora é: {manager.get_active_version()}")

    # 5. Verificar que versões antigas ainda funcionam
    print("\n5. Testando backward compatibility...")
    print("   Descriptografando dados antigos (v1)...")
    for version, ct in ciphertexts_v1:
        version_used, pt = manager.decrypt(ct)
        print(f"   ✓ Recuperado com {version_used}: {pt.decode()}")
        assert version_used == "v1", "Deveria usar v1 para dados antigos"

    # 6. Novos dados usam v2
    print("\n6. Criptografando novos dados (devem usar v2)...")
    new_data = [
        b"Documento novo 1",
        b"Documento novo 2",
        b"Documento novo 3",
    ]

    ciphertexts_v2 = []
    for data in new_data:
        version, ct = manager.encrypt(data)
        ciphertexts_v2.append((version, ct))
        print(f"   ✓ Criptografado com {version}: {data.decode()}")
        assert version == "v2", "Novos dados devem usar v2"

    # 7. Descriptografar dados v2
    print("\n7. Descriptografando dados v2...")
    for version, ct in ciphertexts_v2:
        version_used, pt = manager.decrypt(ct)
        print(f"   ✓ Recuperado com {version_used}: {pt.decode()}")

    # 8. Rotacionar novamente para v3
    print("\n8. Segunda rotação para v3...")
    manager.rotate_to_new_version(
        new_version="v3",
        new_key="even-stronger-password",
        new_salt=b"newest-salt",
    )
    print(f"   ✓ Versão ativa agora é: {manager.get_active_version()}")

    # 9. Verificar que TODAS as versões antigas ainda funcionam
    print("\n9. Testando backward compatibility completa...")
    print("   Descriptografando dados v1...")
    for version, ct in ciphertexts_v1:
        version_used, pt = manager.decrypt(ct)
        print(f"   ✓ v1 OK: {pt.decode()}")

    print("   Descriptografando dados v2...")
    for version, ct in ciphertexts_v2:
        version_used, pt = manager.decrypt(ct)
        print(f"   ✓ v2 OK: {pt.decode()}")

    # 10. Persistir configuração em arquivo .env
    print("\n10. Persistindo configuração em arquivo .env...")
    env_file = Path("example_secrets.env")

    # Rotacionar e persistir
    manager.rotate_to_new_version(
        new_version="v4",
        new_key="file-persisted-key",
        new_salt=b"file-salt",
        persist_to_file=str(env_file),
    )
    print(f"   ✓ Configuração salva em: {env_file}")
    print("\n   Conteúdo do arquivo:")
    if env_file.exists():
        with env_file.open() as f:
            for line in f:
                if not line.startswith("#"):
                    print(f"   {line.rstrip()}")

    # 11. Estatísticas finais
    print("\n11. Estatísticas finais:")
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    # 12. Listar todas as versões
    print("\n12. Versões disponíveis:")
    versions = manager.get_all_versions()
    for v in versions:
        indicator = "← ATIVA" if v == manager.get_active_version() else ""
        print(f"   - {v} {indicator}")

    # 13. Limpar material criptográfico sensível
    print("\n13. Limpando material sensível da memória...")
    manager.cleanup()
    print("   ✓ Limpeza de segurança concluída")

    # Cleanup
    if env_file.exists():
        os.remove(env_file)
        print(f"\n✓ Arquivo de exemplo removido: {env_file}")

    print("\n=== Fim do exemplo de rotação ===\n")


if __name__ == "__main__":
    main()
