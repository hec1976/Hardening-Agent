#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

install_ollama=0
pull_model=0
optimize_ollama=0
model="qwen3:14b"
operator="${SUDO_USER:-}"

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/bootstrap-debian.sh [options]

Options:
  --install-ollama       Install Ollama from the official installer when missing
  --pull-model           Pull the configured model after the API is reachable
  --optimize-ollama      Tune the local service for one 14B model and 8 GB VRAM
  --model NAME           Ollama model (default: qwen3:14b)
  --operator USER        Unprivileged GUI/operator account; required after plain su
  -h, --help             Show this help

Example after "su -":
  ./scripts/bootstrap-debian.sh --operator hec --install-ollama --pull-model --optimize-ollama
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-ollama) install_ollama=1 ;;
        --pull-model) pull_model=1 ;;
        --optimize-ollama) optimize_ollama=1 ;;
        --model)
            [[ $# -ge 2 ]] || { echo "--model requires a value" >&2; exit 2; }
            model="$2"
            shift
            ;;
        --operator)
            [[ $# -ge 2 ]] || { echo "--operator requires a value" >&2; exit 2; }
            operator="$2"
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root with sudo or su: sudo $0" >&2
    exit 77
fi

if [[ ! "${model}" =~ ^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$ ]]; then
    echo "Unsafe Ollama model name" >&2
    exit 2
fi

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
fi
if [[ "${ID:-}" != "debian" && "${ID:-}" != "ubuntu" ]]; then
    echo "This bootstrap script supports Debian and Ubuntu agent hosts only." >&2
    exit 1
fi

apt-get update
apt-get install -y \
    ca-certificates curl git jq libvirt-clients openssh-client passwd \
    python3 python3-setuptools python3-venv python3-wheel shellcheck

if [[ -n "${operator}" ]]; then
    if ! id "${operator}" >/dev/null 2>&1; then
        echo "Operator user does not exist: ${operator}" >&2
        exit 1
    fi
    if getent group libvirt >/dev/null 2>&1; then
        if ! id -nG "${operator}" | tr ' ' '\n' | grep -Fqx libvirt; then
            usermod -aG libvirt "${operator}"
            echo "Added ${operator} to libvirt. Log out and back in before starting the GUI."
        fi
    else
        echo "WARNING: libvirt group is unavailable; KVM listing may require host configuration."
    fi
elif [[ -z "${SUDO_USER:-}" ]]; then
    echo "WARNING: plain su detected. Use --operator hec to configure KVM permissions."
fi

ollama_service_available() {
    systemctl cat ollama.service >/dev/null 2>&1
}

if ! command -v ollama >/dev/null 2>&1 || ! ollama_service_available; then
    if [[ "${install_ollama}" -eq 1 ]]; then
        installer="$(mktemp)"
        trap 'rm -f -- "${installer}"' EXIT
        curl -fsSL https://ollama.com/install.sh -o "${installer}"
        sh "${installer}"
    else
        echo "Ollama or its service is incomplete. Re-run with --install-ollama to repair it."
    fi
fi

if command -v ollama >/dev/null 2>&1; then
    if [[ "${optimize_ollama}" -eq 1 ]]; then
        if ! ollama_service_available; then
            echo "Cannot optimize Ollama: ollama.service is unavailable." >&2
            exit 1
        fi
        install -d -m 0755 /etc/systemd/system/ollama.service.d
        cat > /etc/systemd/system/ollama.service.d/10-linux-hardening-agent.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_CONTEXT_LENGTH=4096"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_KEEP_ALIVE=10m"
Environment="OLLAMA_NO_CLOUD=1"
EOF
        systemctl daemon-reload
        echo "Applied conservative Ollama settings for qwen3:14b and 8 GB VRAM."
    fi
    if ollama_service_available; then
        systemctl enable --now ollama
    fi
    api_ready=0
    for _attempt in $(seq 1 30); do
        if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
            api_ready=1
            break
        fi
        sleep 1
    done
    if [[ "${api_ready}" -eq 1 ]]; then
        echo "Ollama API: reachable"
        if [[ "${pull_model}" -eq 1 ]]; then
            ollama pull "${model}"
        elif ! ollama list | awk 'NR > 1 {print $1}' | grep -Fqx "${model}"; then
            echo "Model ${model} is missing. Re-run with --pull-model."
        fi
    else
        echo "WARNING: Ollama is installed but the local API is unavailable." >&2
    fi
fi

if command -v nvidia-smi >/dev/null 2>&1; then
    echo
    nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
else
    echo "WARNING: nvidia-smi is unavailable; Ollama may run on CPU only."
fi

echo
echo "System prerequisites are ready."
if [[ -n "${operator}" ]]; then
    echo "Continue as ${operator}:"
    echo "  su - ${operator}"
fi
echo "  cd $(dirname -- "$(dirname -- "$(readlink -f -- "$0")")")"
echo "  ./scripts/install-local.sh"
