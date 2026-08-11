#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

if [[ "${EUID}" -eq 0 ]]; then
    echo "Run this script as the normal operator user." >&2
    exit 77
fi

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
port=8765
previous=""
for argument in "$@"; do
    if [[ "${previous}" == "--port" && "${argument}" =~ ^[0-9]{1,5}$ ]]; then
        port="${argument}"
    fi
    previous="${argument}"
done

if command -v fuser >/dev/null 2>&1; then
    mapfile -t pids < <(fuser -n tcp "${port}" 2>/dev/null | tr ' ' '\n' | sed '/^$/d' | sort -u)
else
    pids=()
fi

for pid in "${pids[@]}"; do
    owner_uid="$(ps -o uid= -p "${pid}" 2>/dev/null | tr -d ' ')"
    command_line="$(ps -o args= -p "${pid}" 2>/dev/null || true)"
    if [[ "${owner_uid}" != "${EUID}" ]]; then
        echo "Port ${port} is used by PID ${pid} owned by another user." >&2
        echo "Stop that process explicitly, then run this script again." >&2
        exit 1
    fi
    if [[ "${command_line}" != *hardening-agent* || "${command_line}" != *gui* ]]; then
        echo "Port ${port} is occupied by an unrelated process: ${command_line}" >&2
        exit 1
    fi
    echo "Stopping old Linux Hardening Agent process ${pid} ..."
    kill -TERM "${pid}"
done

for _attempt in {1..30}; do
    if ! (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

exec "${project_dir}/scripts/start-gui.sh" "$@"
