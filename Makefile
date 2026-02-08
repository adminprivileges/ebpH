SHELL := /usr/bin/env bash

# User-configurable 
# python packages are pretty tightly coupled, its a good idea to keep 3.8 to avoid build errors
PYTHON_VERSION ?= 3.8.18
VENV_NAME ?= py38-bpf
PYENV_ROOT ?= $(HOME)/.pyenv
# Where to build BCC from source (pinned checkout is recommended for reproducibility)
BCC_DIR ?= $(HOME)/src/bcc

# Setup pyenv ay pyenv-virtualenvironment
VENV_PREFIX := $(PYENV_ROOT)/versions/$(VENV_NAME)
VENV_PY := $(VENV_PREFIX)/bin/python
PIP := $(VENV_PY) -m pip

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make -f Makefile.pyenv deps-apt"
	@echo "  make -f Makefile.pyenv pyenv-install"
	@echo "  make -f Makefile.pyenv pyenv-venv"
	@echo "  make -f Makefile.pyenv bcc-build"
	@echo "  make -f Makefile.pyenv dev|install"
	@echo "  make -f Makefile.pyenv systemd-install"
	@echo "  make -f Makefile.pyenv status|logs"

# Install all dependencies via apt
.PHONY: deps-apt
deps-apt:
	sudo apt-get update
	sudo apt-get install -y \
	  build-essential curl git ca-certificates \
	  libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
	  libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev \
	  cmake bison flex libedit-dev libelf-dev libfl-dev zlib1g-dev liblzma-dev \
	  libllvm14 llvm-14-dev clang-14 libclang-14-dev libclang-cpp14-dev \
	  linux-headers-$$(uname -r) \
	  luajit libluajit-5.1-dev iputils-arping netperf iperf3\
	  zip

# install pyenv from the git repo
# TODO: edit this to just put the stuff in ~.bashrc, or make a user configutable shell in initiall vars
.PHONY: pyenv-install
pyenv-install:
	@[ -d "$(PYENV_ROOT)" ] || git clone https://github.com/pyenv/pyenv.git "$(PYENV_ROOT)"
	@[ -d "$(PYENV_ROOT)/plugins/pyenv-virtualenv" ] || git clone https://github.com/pyenv/pyenv-virtualenv.git "$(PYENV_ROOT)/plugins/pyenv-virtualenv"
	@echo "Ensure your shell init contains:"
	@echo '  export PYENV_ROOT="$$HOME/.pyenv"'
	@echo '  export PATH="$$PYENV_ROOT/bin:$$PATH"'
	@echo '  eval "$$(pyenv init -)"'
	@echo '  eval "$$(pyenv virtualenv-init -)"'

# Installing actually installing the python versiona nd setting up our pyenv here.
.PHONY: pyenv-venv
pyenv-venv:
	@command -v pyenv >/dev/null || (echo "pyenv not on PATH. Open a new shell after updating your shell init."; exit 1)
	pyenv install -s $(PYTHON_VERSION)
	pyenv virtualenv -f $(PYTHON_VERSION) $(VENV_NAME)
	$(VENV_PY) -m pip install -U pip setuptools wheel
	@echo "Venv ready at: $(VENV_PREFIX)"

# Double check that the pyenv is even there
.PHONY: venv-check
venv-check:
	@test -x "$(VENV_PY)" || (echo "Missing venv python at $(VENV_PY). Run: make -f Makefile.pyenv pyenv-venv"; exit 1)

# Build/install BCC into the pyenv venv, and patch out Debian-only --install-layout=deb
# This the deb patch out is very necessary as the option will not be recognized and your build will fail without
.PHONY: bcc-build
bcc-build: venv-check
	@if [ ! -d "$(BCC_DIR)/.git" ]; then \
	  echo "Cloning BCC into $(BCC_DIR)"; \
	  mkdir -p "$$(dirname "$(BCC_DIR)")"; \
	  git clone https://github.com/iovisor/bcc.git "$(BCC_DIR)"; \
	fi
	cd "$(BCC_DIR)" && git submodule update --init --recursive
	# Patch Debian-specific install flag (pyenv CPython doesn't support it)
	@grep -R --line-number "install-layout" "$(BCC_DIR)" | head -n 1 >/dev/null && \
	  (echo "Patching --install-layout deb out of BCC build scripts"; \
	   grep -R --line-number "install-layout" "$(BCC_DIR)" | awk -F: '{print $$1}' | sort -u | xargs -r sed -i 's/--install-layout deb//g') || true
	rm -rf "$(BCC_DIR)/build-py38"
	mkdir -p "$(BCC_DIR)/build-py38"
	cd "$(BCC_DIR)/build-py38" && \
	  cmake .. -DPYTHON_CMD="$(VENV_PY)" -DCMAKE_INSTALL_PREFIX="$(VENV_PREFIX)" && \
	  make -j"$$(nproc)"
	# Install core + python bindings into the venv prefix
	cd "$(BCC_DIR)/build-py38" && cmake --install .
	@echo "Testing bcc import in venv..."
	LD_LIBRARY_PATH="$(VENV_PREFIX)/lib:/usr/local/lib:/usr/lib/x86_64-linux-gnu:$$LD_LIBRARY_PATH" \
	$(VENV_PY) -c "import bcc; from bcc import BPF; print('bcc OK:', bcc.__file__)"

.PHONY: dev
dev: venv-check
	$(PIP) install -e . -r requirements.txt

.PHONY: install
install: venv-check
	$(PIP) install . --compile -r requirements.txt

# Install a systemd unit that runs ebphd from the venv
.PHONY: systemd-install
systemd-install: venv-check
	./systemd/install_service.sh "$(VENV_PREFIX)" "$$(pwd)"

.PHONY: status
status:
	sudo systemctl status ebphd.service --no-pager || true

.PHONY: logs
logs:
	sudo journalctl -u ebphd.service -e --no-pager || true
