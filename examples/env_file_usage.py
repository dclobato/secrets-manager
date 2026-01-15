"""Exemplo de uso de SecretsConfig.from_file() e SecretsConfig.to_file()."""

from pathlib import Path

from secrets_manager import SecretsConfig, SecretsManager


def main() -> None:
    """Demonstra persistencia e carga de configuracao via arquivo .env."""
    env_path = Path("example_secrets.env")

    # 1) Criar configuracao em memoria
    config = SecretsConfig(
        keys={"v1": {"key": "example-key", "salt": b"example-salt"}},  # salt em bytes
        active_version="v1",
    )

    # 2) Salvar a configuracao no arquivo (metodo de instancia)
    config.to_file(str(env_path))
    print(f"Configuracao salva em: {env_path}")

    # 3) Carregar a configuracao do arquivo (class method)
    loaded = SecretsConfig.from_file(str(env_path))

    # 4) Inicializar o manager com a configuracao carregada
    manager = SecretsManager(loaded)

    version, ciphertext = manager.encrypt(b"payload")
    _, plaintext = manager.decrypt(ciphertext)
    print(f"Versao usada: {version}")
    print(f"Texto claro: {plaintext.decode('utf-8')}")

    # 5) A configuracao continua acessivel via manager.config
    manager.config.to_file(str(env_path))

    # 6) Rotacionar chaves e salvar preservando variaveis existentes (append=True)
    manager.rotate_to_new_version("v2", "rotated-key", b"rotated-salt")
    manager.config.to_file(str(env_path), append=True)
    print("\nConteudo final do arquivo .env:")
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("#"):
                continue
            print(f"  {line}")

    # Cleanup do arquivo de exemplo
    if env_path.exists():
        env_path.unlink()


if __name__ == "__main__":
    main()
