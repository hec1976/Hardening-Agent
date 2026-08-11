#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

if [[ "${EUID}" -eq 0 ]]; then
    echo "Do not install the local agent or run its GUI as root." >&2
    echo "Leave su with 'exit', then run this script as your normal operator user." >&2
    exit 77
fi

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
venv_dir="${LHA_VENV:-${project_dir}/.venv}"

command -v python3 >/dev/null
if [[ -e "${venv_dir}" && ! -w "${venv_dir}" ]]; then
    echo "The virtual environment is not writable by $(id -un): ${venv_dir}" >&2
    echo "If it was created as root, correct its ownership or remove it before retrying." >&2
    exit 1
fi
if [[ -d "${venv_dir}" && ! -x "${venv_dir}/bin/python" ]]; then
    echo "The existing virtual environment is incomplete: ${venv_dir}" >&2
    echo "Rename it for recovery, then run this installer again as $(id -un)." >&2
    exit 1
fi

if [[ ! -d "${venv_dir}" ]]; then
    python3 -m venv --system-site-packages "${venv_dir}"
fi
if ! "${venv_dir}/bin/python" -m pip --version >/dev/null 2>&1; then
    echo "pip fehlt in der virtuellen Umgebung; versuche ensurepip ..."
    if ! "${venv_dir}/bin/python" -m ensurepip --upgrade; then
        echo "pip konnte nicht eingerichtet werden. Installiere python3-venv und starte das Setup erneut." >&2
        exit 1
    fi
fi
echo "Updating Python build tools in ${venv_dir} ..."
"${venv_dir}/bin/python" -m pip install --upgrade pip setuptools wheel

echo "Installing Linux Hardening Agent ..."
"${venv_dir}/bin/python" -m pip install --no-build-isolation -e "${project_dir}"

operator_user="$(id -un)"
agent="${venv_dir}/bin/hardening-agent"

requested_models=()
model_selection="${LHA_INSTALL_MODELS:-ask}"
if command -v ollama >/dev/null 2>&1; then
    if [[ "${model_selection}" == "ask" && -t 0 && -t 1 ]]; then
        printf '\nWelche Ollama-Modelle sollen installiert werden?\n'
        printf '  1) qwen3:8b  (empfohlen für 8 GB VRAM)\n'
        printf '  2) qwen3:14b (langsamer, benötigt zusätzlich RAM)\n'
        printf '  3) Beide Modelle\n'
        printf '  4) Keine Modellinstallation\n'
        read -r -p 'Auswahl [1]: ' model_choice || model_choice=4
        model_choice="${model_choice:-1}"
        case "${model_choice}" in
            1) requested_models=("qwen3:8b") ;;
            2) requested_models=("qwen3:14b") ;;
            3) requested_models=("qwen3:8b" "qwen3:14b") ;;
            4) requested_models=() ;;
            *) echo "Ungültige Auswahl; keine Modelle werden installiert." >&2 ;;
        esac
    elif [[ "${model_selection}" != "ask" && "${model_selection}" != "none" ]]; then
        IFS=',' read -r -a requested_models <<< "${model_selection}"
    fi

    if [[ ${#requested_models[@]} -gt 0 ]]; then
        if ! installed_models="$(ollama list 2>/dev/null)"; then
            echo "Ollama ist installiert, aber die lokale API ist nicht erreichbar." >&2
            echo "Die Modellinstallation wird übersprungen." >&2
        else
            for model_name in "${requested_models[@]}"; do
                if [[ ! "${model_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$ ]]; then
                    echo "Unsicherer Modellname übersprungen: ${model_name}" >&2
                    continue
                fi
                if awk 'NR > 1 {print $1}' <<< "${installed_models}" | grep -Fqx "${model_name}"; then
                    echo "Ollama-Modell bereits installiert: ${model_name}"
                else
                    echo "Installiere Ollama-Modell ${model_name} ..."
                    ollama pull "${model_name}"
                fi
            done
        fi
    fi
else
    echo "Ollama ist nicht installiert; die Modellabfrage wird übersprungen."
    echo "Ollama kann später über scripts/bootstrap-debian.sh installiert werden."
fi

if command -v vagrant >/dev/null 2>&1; then
    echo "Checking Vagrant private-key ownership ..."
    set +e
    access_output="$("${agent}" vagrant-access --operator "${operator_user}" 2>&1)"
    access_status=$?
    set -e
    printf '%s\n' "${access_output}"
    if [[ ${access_status} -eq 3 ]]; then
        echo "Root-owned Vagrant keys detected; ownership remains unchanged."
        echo "Use ./scripts/start-gui.sh so the matching execution mode is selected."
    elif [[ ${access_status} -eq 2 ]]; then
        echo "A Vagrant key is missing or has unsupported permissions." >&2
        echo "No ownership or permission changes were made." >&2
    elif [[ ${access_status} -ne 0 ]]; then
        echo "Vagrant access check failed; installation continues without changing keys." >&2
    fi
fi

printf '\nInstalled for user %s. Run:\n' "$(id -un)"
printf '  %s doctor\n' "${venv_dir}/bin/hardening-agent"
printf '  %s/scripts/start-gui.sh\n' "${project_dir}"
