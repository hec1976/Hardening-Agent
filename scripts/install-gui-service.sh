#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

if [[ "${EUID}" -eq 0 ]]; then
    echo "Run this script as the normal GUI operator, not root." >&2
    exit 77
fi

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
agent="${project_dir}/.venv/bin/hardening-agent"
unit_dir="${HOME}/.config/systemd/user"
unit_path="${unit_dir}/linux-hardening-agent-gui.service"

[[ -x "${agent}" ]] || { echo "Run ./scripts/install-local.sh first." >&2; exit 1; }
mkdir -p -- "${unit_dir}"
cat > "${unit_path}" <<EOF
[Unit]
Description=Linux Hardening Agent local GUI
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${project_dir}
ExecStart=${agent} gui --no-browser
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${project_dir}/output %h/.local/share/linux-hardening-agent

[Install]
WantedBy=default.target
EOF

mkdir -p -- "${project_dir}/output" "${HOME}/.local/share/linux-hardening-agent"
systemctl --user daemon-reload
systemctl --user enable --now linux-hardening-agent-gui.service
echo "GUI service enabled at http://127.0.0.1:8765"
