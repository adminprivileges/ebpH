#!/usr/bin/env bash
set -euo pipefail

VENV_PREFIX="${1:?Usage: install_service.sh /path/to/venv/prefix [/path/to/ebpH]}"
WORKDIR="${2:-$(pwd)}"

SERVICE_PATH="/etc/systemd/system/ebphd.service"

sudo tee "$SERVICE_PATH" >/dev/null <<EOF
[Unit]
Description=ebpH daemon (pyenv Python 3.8)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes

Environment="EBPH_VENV=$VENV_PREFIX"
Environment="PATH=$VENV_PREFIX/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="LD_LIBRARY_PATH=$VENV_PREFIX/lib:/usr/local/lib:/usr/lib/x86_64-linux-gnu"

LimitMEMLOCK=infinity
WorkingDirectory=$WORKDIR

ExecStart=$VENV_PREFIX/bin/ebphd start
ExecStop=$VENV_PREFIX/bin/ebphd stop
ExecReload=$VENV_PREFIX/bin/ebphd restart

User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ebphd.service
sudo systemctl status ebphd.service --no-pager
