#!/usr/bin/env bash
# scripts/bootstrap.sh
#
# PURPOSE
#   Automated install script for ebpH on Ubuntu 22.04.
#   This script is intended for provisioning new vms with minimal human interaction to aide in reproducability.
#
# WHY THIS EXISTS
#   ebpH uses olderpackages (e.g., uvloop==0.14.0, httptools==0.1.1) that
#   fail to compile against newer python versions due to the CPython ABIs (e.g., Python 3.10 on Ubuntu 22.04).
#   To avoid patching those packages, its easier to just install Python 3.8 via pyenv and install ebpH
#   into a dedicated pyenv virtual environment.
#
# STEPS
#   1) Install OS packages needed to build Python (pyenv) and to build BCC/LLVM toolchain
#   2) Install pyenv locally (no shell init edits)
#   3) Build/install Python 3.8 and create a pyenv virtualenv
#   4) Clone/build BCC and install BCC + Python bindings into the pyenv virtualenv
#      - includes patching out Debian-only "setup.py --install-layout=deb" which pyenv CPython lacks
#   5) Register the venv's lib/ with ld.so and run ldconfig (so sudo/root can find libbcc.so.0)
#   6) Install ebpH into the same virtualenv
#   7) Symlink ebph and ebphd into /usr/local/bin (so both user and root can run them via PATH)
#   8) Install and enable a systemd service that runs ebphd using the virtualenv
#
# USAGE
#   From the ebpH repo root:
#     chmod +x scripts/bootstrap.sh
#     bash scripts/bootstrap.sh
#
# OPTIONAL ENV OVERRIDES
#   PYTHON_VERSION=3.8.18
#   VENV_NAME=py38-bpf
#   PYENV_ROOT=$HOME/.pyenv
#   BCC_DIR=$HOME/src/bcc
#   SERVICE_NAME=ebphd
#   EBPH_EDITABLE=0 (1 = dev, 0 install)
#
# NOTE
#   - Do NOT run this script as root. It uses sudo for apt/systemd only.
#   - For safety, It does NOT modify ~/.bashrc or shell init files; it exports 
#     PATH/PYENV_ROOT only for the duration of the script execution.
#   - It is safe to re-run.
#
# -e Exit immediately if any command returns a non-zero
# -u Unset variables cause an error, exit immediately
# -o pipefall in pipelines, the exit status is the first non-zero exit code,
# not just the exit code of the last comand
set -euo pipefail

# Print a helpful message on failure with the line number.
trap 'echo "BOOTSTRAP FAILED at line $LINENO" >&2' ERR

# ------------------------- Config (override via env) -------------------------
# The "-" in front of variable like PYTHON_VERSION:-3.8.18 are bash expansion to preserve 
# the default value of the varibale if its already set.  
# Version of python
PYTHON_VERSION="${PYTHON_VERSION:-3.8.18}"
# Name of the python virtual environment
VENV_NAME="${VENV_NAME:-py38-bpf}"
# Default pyenv root, change this if youve changed yours
PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
# Recommended bcc dir
BCC_DIR="${BCC_DIR:-$HOME/src/bcc}"
# Actual service name, change if you change service name
SERVICE_NAME="${SERVICE_NAME:-ebphd}"
# Run dev or install (default install, i havent really touched dev)
EBPH_EDITABLE="${EBPH_EDITABLE:-0}"

DO_LDCONFIG="${DO_LDCONFIG:-1}"
DO_SYMLINKS="${DO_SYMLINKS:-1}"

# Determine repository root based on this script location.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ------------------------- Helper functions -------------------------
# Helps with error output, die will send errors to stderr instead of stdout and stop the 
# scrpt's execution
die() { echo "ERROR: $*" >&2; exit 1; }
# Double checks to see if a command that i run actually exists, if not, send it to die
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

# Safety: do not run as root; we only use sudo when needed.
if [[ "$(id -u)" -eq 0 ]]; then
  die "Do not run as root. Run as your normal user with sudo privileges."
fi

# Basic tools that must exist before we start.
# TODO: Maybe add these to the dependencies
need_cmd sudo
need_cmd git
need_cmd curl

# make sure we're in the right place, otherwise the rest of the script is gonna yell at us
# and it wouldnt be a good idea to do absolute path for everything
if [[ ! -f "$REPO_ROOT/requirements.txt" ]]; then
  die "Run this from the ebpH repo root (requirements.txt not found). Current: $REPO_ROOT"
fi

# Force apt to run without interactive prompts.
export DEBIAN_FRONTEND=noninteractive

# -------------------- Step 1: OS packages  --------------------
# TODO: Evaluate the potential of making package manager a variable to run on fedora or
# other distros
# Install:
#  - build prereqs for compiling Python (pyenv builds from source)
#  - LLVM/Clang + dev headers for building BCC
#  - kernel headers for your running kernel needed for  BPF
#  - zip because the BCC build/test portion will fail without it
#
echo "[1/8] Installing apt dependencies..."
sudo apt-get update -y
sudo apt-get install -y \
  ca-certificates curl git \
  build-essential pkg-config \
  libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
  libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev \
  cmake bison flex libedit-dev libelf-dev libfl-dev \
  zip \
  linux-headers-$(uname -r) \
  llvm-14 llvm-14-dev libllvm14 \
  clang-14 libclang-14-dev libclang-cpp14-dev \
  libdebuginfod-dev

# -------------------- Step 2: Install pyenv locally --------------------
# We intentionally do NOT edit shell init files (~/.bashrc, etc). Instead, we:
#  - clone pyenv to $PYENV_ROOT (default ~/.pyenv)
#  - clone pyenv-virtualenv plugin
#  - export PATH to include pyenv bins/shims for this script only
#
echo "[2/8] Installing pyenv locally (no shell init edits)..."
if [[ ! -d "$PYENV_ROOT" ]]; then
  git clone https://github.com/pyenv/pyenv.git "$PYENV_ROOT"
fi
if [[ ! -d "$PYENV_ROOT/plugins/pyenv-virtualenv" ]]; then
  git clone https://github.com/pyenv/pyenv-virtualenv.git "$PYENV_ROOT/plugins/pyenv-virtualenv"
fi

export PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"
need_cmd pyenv
export PYENV_SHELL=bash

# TODO: Move this to the end 
echo "If you would like to persist your pyenv path add this to your shell init (~/.bashrc)"
echo 'PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"'
echo 'PYENV_SHELL=bash'

# -------------------- Step 3: Build Python 3.8 + create venv --------------------
# This installs  Python 3.8.18 via pyenv and creates a virtualenv.
# also upgrades pip tooling inside that env.
#
echo "[3/8] Installing Python ${PYTHON_VERSION} and creating venv ${VENV_NAME}..."
pyenv install -s "$PYTHON_VERSION"
pyenv virtualenv -f "$PYTHON_VERSION" "$VENV_NAME"

# Make this venv “local” to the repo directory (creates .python-version).
# this helps pyenv pick the right env when you are in the repo.
pyenv local "$VENV_NAME"

VENV_PREFIX="$PYENV_ROOT/versions/$VENV_NAME"
VENV_PY="$VENV_PREFIX/bin/python"
VENV_PIP="$VENV_PY -m pip"

[[ -x "$VENV_PY" ]] || die "Expected venv python at: $VENV_PY"

# Keep packaging tools current inside the env.
"$VENV_PY" -m pip install -U pip setuptools wheel

# -------------------- Step 4: Clone/update BCC --------------------
# BCC provides eBPF compilation/loading helpers and Python bindings. We build and install
# BCC into the same pyenv virtualenv, so 'import bcc' works with Python 3.8.
#
# IMPORTANT: We build from source to ensure Python bindings are built for Python 3.8.
# Using python3-bpfcc from apt will compile it for the distro’s default Python and cause issues.
#
echo "[4/8] Cloning/updating BCC in ${BCC_DIR}..."
mkdir -p "$(dirname "$BCC_DIR")"
if [[ ! -d "$BCC_DIR/.git" ]]; then
  git clone https://github.com/iovisor/bcc.git "$BCC_DIR"
fi

cd "$BCC_DIR"
# Initializes module dependencies here
git submodule update --init --recursive

# -------------------- Step 5: Patch Debian-only distutils flag --------------------
# Some build scripts for BCC add: setup.py install --install-layout=deb
# That flag exists on Debian/Ubuntu system Python builds, but pyenv CPython does not
# include Debian’s distutils patch, so installation fails with:
#   "error: option --install-layout not recognized"
#
# Removes the flag wherever it appears in the BCC checkout. This is a small local patch
# to make BCC Python binding installation compatible with pyenv Python.


# This isnt going to work due failure condition of searching that will cause the whole script
# to fail, patching offensing file directly
#echo "[5/8] Patching Debian-only --install-layout deb (needed for pyenv CPython)..."
#if grep -R --line-number "install-layout deb" . >/dev/null 2>&1; then
#  grep -R --line-number "install-layout deb" . | awk -F: '{print $1}' | sort -u | \
#    xargs -r sed -i 's/--install-layout deb//g'
#fi
echo "[5/8] Removing Debian-only --install-layout deb flag from BCC python install..."
# I have to patch the offending file directly because of how grep can fail.
PY_CMAKELISTS="$BCC_DIR/src/python/CMakeLists.txt"
[[ -f "$PY_CMAKELISTS" ]] || die "Expected file not found: $PY_CMAKELISTS"

# Remove either "--install-layout deb" or "--install-layout=deb" (with any spacing).
sed -i -E 's/[[:space:]]+--install-layout(=|[[:space:]]+)deb//g' "$PY_CMAKELISTS"

# Hard fail if it’s still present (prevents silent failure)
if grep -nE -- '--install-layout(=|[[:space:]]+)deb' "$PY_CMAKELISTS" >/dev/null; then
  die "Patch failed: --install-layout deb still present in $PY_CMAKELISTS"
fi

# -------------------- Step 6: Build and install BCC into the venv --------------------
# make sure to use the  venv name in the build to avoid mixing root-owned artifacts
# from previous system-level builds and to keep the install target deterministic.
#
# -DPYTHON_CMD points CMake to the pyenv Python 3.8 interpreter.
# -DCMAKE_INSTALL_PREFIX installs BOTH libraries and python bindings into the venv prefix.
#
echo "[6/8] Building BCC and installing into venv prefix: $VENV_PREFIX"

BUILD_DIR="$BCC_DIR/build-$VENV_NAME"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. \
  -DPYTHON_CMD="$VENV_PY" \
  -DCMAKE_INSTALL_PREFIX="$VENV_PREFIX" \
  -DCMAKE_BUILD_TYPE=Release

make -j"$(nproc)"

# Install into venv prefix (no sudo because prefix is under $HOME).
cmake --install .

# Build + install BCC Python bindings into the venv site-packages
echo "[6.25/8] Building/installing BCC Python bindings into venv..."
make -C "$BUILD_DIR/src/python" -j"$(nproc)"

# Force it to use the venv python (works with most bcc Makefiles/CMake glue)
PYTHON_CMD="$VENV_PY" PYTHON="$VENV_PY" make -C "$BUILD_DIR/src/python" install

# Sanity check that the module is actually present now
"$VENV_PY" -c "import bcc; print('bcc module at:', bcc.__file__)"

# Verify bcc import in venv (may still fail before ldconfig if libbcc isn't in default loader paths)
# removing, is likely going to fail and stops script execution
# "$VENV_PY" -c "import bcc; from bcc import BPF; print('bcc python OK:', bcc.__file__)"

# NEW: make libbcc.so.0 resolvable for sudo/root without LD_LIBRARY_PATH
if [[ "$DO_LDCONFIG" == "1" ]]; then
  echo "[6.5/8] Registering venv libs with ld.so (ldconfig)..."
  echo "$VENV_PREFIX/lib" | sudo tee /etc/ld.so.conf.d/ebph-bcc-pyenv.conf >/dev/null
  sudo ldconfig
  ldconfig -p | grep -E 'libbcc\.so' >/dev/null || die "ldconfig did not register libbcc"
fi

# Re-test import after ldconfig
"$VENV_PY" -c "from bcc import BPF; print('bcc OK (post-ldconfig)')"

# -------------------- Step 7: Install ebpH into the venv --------------------
# We install ebpH and its pinned dependencies into the same venv.
# Default is editable install (EBPH_EDITABLE=1) so you can iterate on code.
#
echo "[7/8] Installing ebpH into venv..."
cd "$REPO_ROOT"

if [[ "$EBPH_EDITABLE" == "1" ]]; then
  $VENV_PIP install -e . -r requirements.txt
else
  $VENV_PIP install . --compile -r requirements.txt
fi

# Quick sanity import.
"$VENV_PY" -c "import ebph; print('ebph OK')"

# NEW: put ebph/ebphd on PATH for user + root by symlinking to /usr/local/bin
if [[ "$DO_SYMLINKS" == "1" ]]; then
  echo "[7.5/8] Symlinking ebph/ebphd into /usr/local/bin..."
  [[ -x "$VENV_PREFIX/bin/ebph"  ]] || die "Missing $VENV_PREFIX/bin/ebph"
  [[ -x "$VENV_PREFIX/bin/ebphd" ]] || die "Missing $VENV_PREFIX/bin/ebphd"
  sudo ln -sf "$VENV_PREFIX/bin/ebph"  /usr/local/bin/ebph
  sudo ln -sf "$VENV_PREFIX/bin/ebphd" /usr/local/bin/ebphd
fi

# -------------------- Step 8: Install and enable systemd service --------------------
# ebpH needs elevated privileges for many eBPF operations. systemd will run it as root,
# but we want it to use the virtualenv’s ebphd entrypoint and Python stack.
#
# The unit uses:
#   PATH to prioritize venv bin (so ExecStart uses the venv ebphd)
#   LD_LIBRARY_PATH to include venv lib
#   LimitMEMLOCK=infinity (the internet said i needed this)
#
echo "[8/8] Installing systemd service: ${SERVICE_NAME}.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

sudo tee "$SERVICE_PATH" >/dev/null <<EOF
[Unit]
Description=ebpH daemon (pyenv Python ${PYTHON_VERSION})
After=network.target

[Service]
# oneshot didnt work, simple works better
Type=simple

# used to check with venv is in use
Environment="EBPH_VENV=$VENV_PREFIX"
# Makes sure that the right path is used when executing the tool 
Environment="PATH=$VENV_PREFIX/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# makes sure that the runtime linking can find venv libs as well as local ones if needed
Environment="LD_LIBRARY_PATH=$VENV_PREFIX/lib:/usr/local/lib:/usr/lib/x86_64-linux-gnu"

# useful for ebf, helps make sure the memlock limit isnt inhibiting the script 
LimitMEMLOCK=infinity
# Helps with relative dirs
WorkingDirectory=$REPO_ROOT

ExecStart=$VENV_PREFIX/bin/ebphd start
Restart=on-failure
RestartSec=2
KillSignal=SIGTERM
TimeoutStopSec=30

User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}.service"

# -------------------- Final summary --------------------
echo
echo "SUCCESS"
echo "  Repo:    $REPO_ROOT"
echo "  Pyenv:   $PYENV_ROOT"
echo "  Venv:    $VENV_PREFIX"
echo "  Service: ${SERVICE_NAME}.service"
echo
echo "Useful commands:"
echo "  ebph admin status"
echo "  sudo ebph admin status"
echo "  sudo systemctl status ${SERVICE_NAME}.service --no-pager"
echo "  sudo journalctl -u ${SERVICE_NAME}.service -e --no-pager"
echo
echo "To use the venv interactively (without shell init edits), run:"
echo "  export PYENV_ROOT=\"$PYENV_ROOT\""
echo "  export PATH=\"$PYENV_ROOT/bin:$PYENV_ROOT/shims:\$PATH\""
echo "  cd \"$REPO_ROOT\" && pyenv local \"$VENV_NAME\" && python -V"
