# Wifi Auto Handshaker PMKID — common tasks.
# Authorized WiFi security testing only. Capture only (no cracking).

PY        ?= python3
VENV      := .venv
VENV_PY   := $(VENV)/bin/python
VENV_PIP  := $(VENV)/bin/pip

.PHONY: help venv install dev test lint compile doctor selftest report clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create a virtualenv and install runtime deps
	$(PY) -m venv $(VENV)
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -r requirements.txt

install: ## Install the package (editable) into the active interpreter
	$(PY) -m pip install -e .

dev: ## Install dev/test dependencies
	$(VENV_PIP) install -r requirements-dev.txt

test: ## Run the full test suite
	$(VENV_PY) -m pytest tests/ -q

ci: ## Offline CI: pytest + pyflakes (no wireless hardware)
	$(PY) scripts/ci.sh

lint: ## Lint with pyflakes
	$(VENV_PY) -m pyflakes handshaker/ tests/ bootstrap.py

compile: ## Byte-compile every source file
	$(VENV_PY) -c "import py_compile,pathlib;[py_compile.compile(str(f),doraise=True) for f in pathlib.Path('handshaker').rglob('*.py')];print('compile OK')"

doctor: ## Run the system self-check
	$(VENV_PY) -m handshaker doctor

selftest: ## Run the guided hardware self-test (needs sudo + adapter)
	$(VENV_PY) -m handshaker selftest

report: ## Show captured artifacts + learning state
	$(VENV_PY) -m handshaker report

clean: ## Remove bytecode caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
