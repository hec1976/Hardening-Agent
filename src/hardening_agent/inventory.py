from __future__ import annotations

from datetime import UTC, datetime

from .models import Inventory, Platform, Target
from .transport import Transport, TransportError

INVENTORY_SCRIPT = r"""
set +e
export LC_ALL=C

section() {
    printf '\n@@LHA_SECTION:%s@@\n' "$1"
}

section os_release
if [ -r /etc/os-release ]; then cat /etc/os-release; fi

section kernel
uname -a 2>&1

section identity
id 2>&1

section virtualization
systemd-detect-virt 2>&1 || true

section listening
ss -lntup 2>&1 || netstat -lntup 2>&1 || true

section services
systemctl list-unit-files --type=service --state=enabled 2>&1 || true

section mounts
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 || mount 2>&1 || true

section sshd_effective
if command -v sshd >/dev/null 2>&1; then
    sudo -n sshd -T 2>&1 || sshd -T 2>&1 || true
fi

section firewall
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --state 2>&1
    firewall-cmd --list-all 2>&1
elif command -v nft >/dev/null 2>&1; then
    sudo -n nft list ruleset 2>&1 || nft list ruleset 2>&1 || true
elif command -v ufw >/dev/null 2>&1; then
    ufw status verbose 2>&1 || true
fi

section lsm
cat /sys/kernel/security/lsm 2>&1 || true
command -v aa-status >/dev/null 2>&1 && aa-status 2>&1 || true
command -v getenforce >/dev/null 2>&1 && getenforce 2>&1 || true

section audit
command -v auditctl >/dev/null 2>&1 && (sudo -n auditctl -s 2>&1 || auditctl -s 2>&1) || true

section sysctl
for key in \
    kernel.kptr_restrict kernel.dmesg_restrict kernel.randomize_va_space \
    fs.suid_dumpable fs.protected_hardlinks fs.protected_symlinks \
    net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
    net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
    net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies \
    net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects
do
    sysctl "$key" 2>&1 || true
done

section updates
if command -v zypper >/dev/null 2>&1; then
    zypper -q lu 2>&1 || true
elif command -v apt-get >/dev/null 2>&1; then
    apt-get -s upgrade 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
    dnf -q check-update 2>&1 || true
fi

section compliance
for tool in oscap usg; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf 'TOOL:%s=%s\n' "$tool" "$(command -v "$tool")"
    fi
done
for path in /usr/local/share/xml/scap/ssg/content/ssg-*-ds.xml /usr/share/xml/scap/ssg/content/ssg-*-ds.xml /usr/share/scap-security-guide/ssg-*-ds.xml; do
    if [ -f "$path" ]; then
        rule_count="$(grep -o 'xccdf_org\.ssgproject\.content_rule_[A-Za-z0-9_.-]*' "$path" 2>/dev/null | sort -u | wc -l)"
        profile_count="$(grep -o 'xccdf_org\.ssgproject\.content_profile_[A-Za-z0-9_.-]*' "$path" 2>/dev/null | sort -u | wc -l)"
        printf 'DATASTREAM:%s|%s|%s\n' "$path" "$rule_count" "$profile_count"
        grep -o 'xccdf_org\.ssgproject\.content_rule_[A-Za-z0-9_.-]*' "$path" 2>/dev/null \
            | sort -u | awk -v stream="$path" '{ print "SCAP_RULE:" stream "|" $0 }' \
            | head -120
        # Profile IDs are part of the signed/package-managed SCAP XML. Reading them
        # directly is deterministic and avoids depending on oscap info formatting.
        grep -o 'xccdf_org\.ssgproject\.content_profile_[A-Za-z0-9_.-]*' "$path" 2>/dev/null \
            | sort -u | awk -v stream="$path" '{ print "PROFILE:" stream "|" $0 }' \
            | head -100
    fi
done

section end
"""


def _parse_sections(output: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in output.splitlines():
        if line.startswith("@@LHA_SECTION:") and line.endswith("@@"):
            current = line.removeprefix("@@LHA_SECTION:").removesuffix("@@")
            sections[current] = []
        elif current:
            sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def detect_platform(os_release: str) -> Platform:
    values: dict[str, str] = {}
    for line in os_release.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = _unquote(value)
    distro = values.get("ID", "unknown").lower()
    version = values.get("VERSION_ID", "unknown")
    pretty = values.get("PRETTY_NAME", f"{distro} {version}")

    if distro in {"opensuse-leap", "opensuse-tumbleweed"} or distro in {"sles", "sled"}:
        family = "suse"
    elif distro in {"debian", "ubuntu"}:
        family = "debian"
    elif distro in {"rhel", "rocky", "almalinux", "centos", "fedora", "ol"}:
        family = "rhel"
    else:
        family = "unknown"
    return Platform(family=family, distribution=distro, version=version, pretty_name=pretty)


def collect_inventory(target: Target) -> Inventory:
    result = Transport(target).run_script(INVENTORY_SCRIPT, timeout=180)
    if result.returncode != 0 and not result.stdout:
        raise TransportError(result.stderr.strip() or "Inventory collection failed")
    sections = _parse_sections(result.stdout)
    warnings: list[str] = []
    if result.stderr.strip():
        warnings.append(result.stderr.strip())
    if "os_release" not in sections:
        warnings.append("Target did not return /etc/os-release")
    platform = detect_platform(sections.get("os_release", ""))
    if platform.family == "unknown":
        warnings.append(f"Unsupported or unknown distribution: {platform.distribution}")
    return Inventory(
        target=target.name,
        collected_at=datetime.now(UTC).isoformat(),
        platform=platform,
        sections=sections,
        warnings=warnings,
    )
