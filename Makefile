.PHONY: help install install-dev test test-cov format lint type-check clean build upload docs dev check

help:
	@echo "SecretsManager - Makefile"
	@echo ""
	@echo "Comandos disponíveis:"
	@echo "  make install        - Sincroniza dependências"
	@echo "  make install-dev    - Sincroniza dependências de desenvolvimento"
	@echo "  make test           - Executa testes"
	@echo "  make test-cov       - Executa testes com coverage"
	@echo "  make format         - Formata código com black e isort"
	@echo "  make lint           - Verifica código com flake8"
	@echo "  make type-check     - Verifica tipos com mypy"
	@echo "  make clean          - Limpa arquivos temporários"
	@echo "  make build          - Cria distribuição do pacote"
	@echo "  make upload         - Faz upload para PyPI (requer credenciais)"
	@echo "  make docs           - Gera documentação"

install:
	uv sync

install-dev:
	uv sync --extra dev

test:
	uv run pytest -v

test-cov:
	uv run pytest -v --cov=secrets_manager --cov-report=term-missing --cov-report=html

format:
	uv run black src/ tests/ examples/
	uv run isort src/ tests/ examples/

lint:
	uv run flake8 src/ tests/ --max-line-length=100 --extend-ignore=E203,W503

type-check:
	uv run mypy src/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build: clean
	uv build

upload: build
	uv publish

docs:
	@echo "Documentação disponível no README.md"
	@echo "Para mais documentação, consulte a pasta docs/"

dev: install-dev

check: format lint type-check test-cov
	@echo "✅ Todas as verificações passaram!"
