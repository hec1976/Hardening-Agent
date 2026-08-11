#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

if [[ "${EUID}" -eq 0 ]]; then
    echo "Run this launcher as the normal operator user; it invokes su only when needed." >&2
    exit 77
fi

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
agent="${project_dir}/.venv/bin/hardening-agent"
operator_user="$(id -un)"
operator_home="$(getent passwd "${operator_user}" | cut -d: -f6)"

[[ -x "${agent}" ]] || { echo "Run ./scripts/install-local.sh first." >&2; exit 1; }
[[ -n "${operator_home}" ]] || { echo "Unable to resolve the operator home." >&2; exit 1; }

set +e
"${agent}" vagrant-access --operator "${operator_user}"
access_status=$?
set -e

if [[ ${access_status} -eq 0 ]]; then
    exec "${agent}" gui "$@"
fi

if [[ ${access_status} -eq 3 ]]; then
    command -v su >/dev/null || { echo "su is required for root-owned Vagrant keys." >&2; exit 1; }
    printf 'Vagrant uses root-owned keys; starting the GUI through su.\n'
    printf -v root_command '%q ' env \
        "LHA_OPERATOR=${operator_user}" \
        "${agent}" gui --allow-root --no-browser "$@"
    exec su -c "${root_command}"
fi

echo "Vagrant access is incomplete. No key ownership or permissions were changed." >&2
exit 1
