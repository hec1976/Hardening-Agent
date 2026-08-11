from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

BASELINE_LEVELS = {
    "basic": {"rank": 1, "title": "Basis", "description": "Sichere Grundeinstellungen"},
    "elevated": {
        "rank": 2,
        "title": "Erhöht",
        "description": "Zusätzliche Härtung für produktive Server",
    },
    "critical": {
        "rank": 3,
        "title": "Kritisch",
        "description": "Strenge Kontrollen für besonders schützenswerte Systeme",
    },
}

BASELINE_CATEGORIES = {
    "updates": "Updates und Paketquellen",
    "services": "Dienste und minimale Installation",
    "accounts": "Benutzer, Passwörter und PAM",
    "privileges": "Root-Zugriff und sudo",
    "ssh": "SSH und Fernadministration",
    "filesystem": "Dateisysteme und Dateirechte",
    "kernel": "Kernel und Schutzmechanismen",
    "network": "Netzwerk und Firewall",
    "logging": "Protokollierung und Audit",
    "integrity": "Integrität und Malware-Prävention",
    "crypto": "Kryptografie",
    "operations": "Betrieb, Backup und Wiederherstellung",
}

SYSTEM_ROLES = {
    "general-server": {
        "title": "Allgemeiner Server",
        "description": "Ausgewogene Basis für einen gewöhnlichen Linux-Server.",
        "sensitive_categories": ["network", "ssh", "services", "filesystem"],
    },
    "mail-server": {
        "title": "Mailserver",
        "description": "Schützt Mailfluss, Remotezugriff, TLS und benötigte Maildienste.",
        "sensitive_categories": ["network", "ssh", "services", "crypto", "filesystem"],
    },
    "web-server": {
        "title": "Webserver",
        "description": "Berücksichtigt HTTP(S), TLS, Firewall und Webdienst-Verfügbarkeit.",
        "sensitive_categories": ["network", "services", "crypto", "filesystem"],
    },
    "database-server": {
        "title": "Datenbankserver",
        "description": "Berücksichtigt Datenpfade, Netzwerkbindung und Datenbank-Verfügbarkeit.",
        "sensitive_categories": ["network", "services", "filesystem", "kernel"],
    },
    "virtualization-host": {
        "title": "KVM-/Virtualisierungshost",
        "description": "Schützt Managementzugang, Bridges, Storage und laufende Gäste.",
        "sensitive_categories": ["network", "services", "filesystem", "kernel", "ssh"],
    },
    "workstation": {
        "title": "Arbeitsstation",
        "description": "Berücksichtigt Desktop-, Benutzer- und lokale Gerätedienste.",
        "sensitive_categories": ["services", "network", "accounts", "filesystem"],
    },
}

BASELINE_SOURCES = {
    "anssi": {
        "id": "ANSSI-BP-028",
        "publisher": "ANSSI",
        "title": "Configuration recommendations of a GNU/Linux system",
        "url": (
            "https://messervices.cyber.gouv.fr/guides/"
            "en-configuration-recommendations-gnulinux-system"
        ),
        "scope": "Technische, distributionsübergreifende GNU/Linux-Härtung",
    },
    "bsi": {
        "id": "BSI SYS.1.3",
        "publisher": "BSI",
        "title": "Server unter Linux und Unix",
        "url": (
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/"
            "IT-GS-Kompendium_Einzel_PDFs_2023/07_SYS_IT_Systeme/"
            "SYS_1_3_Server_unter_Linux_und_Unix_Edition_2023.pdf"
            "?__blob=publicationFile&v=3"
        ),
        "scope": "Technische und organisatorische Grundabsicherung von Linux-Servern",
    },
    "nist": {
        "id": "NIST SP 800-123",
        "publisher": "NIST",
        "title": "Guide to General Server Security",
        "url": "https://csrc.nist.gov/pubs/sp/800/123/final",
        "scope": "Sicherer Aufbau und Betrieb allgemeiner Netzwerkserver",
    },
}


def _control(
    control_id: str,
    title: str,
    category: str,
    level: str,
    rationale: str,
    patterns: tuple[str, ...] = (),
    sources: tuple[str, ...] = ("anssi", "bsi"),
    manual: str = "",
) -> dict[str, Any]:
    return {
        "id": control_id,
        "title": title,
        "category": category,
        "level": level,
        "rationale": rationale,
        "patterns": patterns,
        "sources": sources,
        "manual": manual,
    }


GENERAL_LINUX_CONTROLS = [
    _control(
        "GLB-UPD-001",
        "Sicherheitsupdates zeitnah einspielen",
        "updates",
        "basic",
        "Bekannte Schwachstellen sollen durch Herstellerupdates geschlossen werden.",
        ("security_patches_up_to_date", "package_update", "software_update"),
        ("anssi", "bsi", "nist"),
        "Updateprozess, Wartungsfenster und Reaktionszeiten organisatorisch nachweisen.",
    ),
    _control(
        "GLB-UPD-002",
        "Nur vertrauenswürdige und signierte Paketquellen verwenden",
        "updates",
        "basic",
        "Paketquellen und Signaturen schützen die Software-Lieferkette.",
        ("ensure_gpgcheck", "repo_gpgcheck", "package_gpgcheck"),
        ("anssi", "bsi", "nist"),
        "Aktive Repositorys und Schlüsselherkunft zusätzlich manuell prüfen.",
    ),
    _control(
        "GLB-SVC-001",
        "Nicht benötigte Dienste und Pakete entfernen oder deaktivieren",
        "services",
        "basic",
        "Jeder unnötige Dienst vergrößert die Angriffsfläche.",
        (
            "service_avahi-daemon_disabled",
            "service_cups_disabled",
            "service_telnet_disabled",
            "service_rsh_disabled",
            "service_tftp_disabled",
            "package_telnet_removed",
            "package_rsh_removed",
        ),
        ("anssi", "bsi", "nist"),
        "Soll-Dienste anhand der tatsächlichen Serverrolle freigeben.",
    ),
    _control(
        "GLB-SVC-002",
        "Zeitsynchronisation aktivieren",
        "services",
        "basic",
        "Korrekte Zeit ist für Protokolle, Zertifikate und Nachvollziehbarkeit erforderlich.",
        ("package_chrony_installed", "service_chronyd_enabled", "chronyd_", "timesyncd_"),
    ),
    _control(
        "GLB-ACC-001",
        "Leere Passwörter verhindern",
        "accounts",
        "basic",
        "Konten ohne Passwort erlauben eine unmittelbare Umgehung der Authentisierung.",
        ("no_empty_passwords", "sshd_disable_empty_passwords"),
    ),
    _control(
        "GLB-ACC-002",
        "Passwortqualität über PAM erzwingen",
        "accounts",
        "basic",
        "Mindestlänge und Qualitätskontrollen erschweren triviale Kennwörter.",
        ("accounts_password_pam_", "accounts_passwords_pam_", "pam_pwquality"),
    ),
    _control(
        "GLB-ACC-003",
        "Fehlversuche begrenzen und Konten schützen",
        "accounts",
        "elevated",
        "Begrenzung wiederholter Fehlversuche reduziert automatisierte Passwortangriffe.",
        ("faillock", "pam_tally", "accounts_passwords_pam_faillock"),
    ),
    _control(
        "GLB-ACC-004",
        "Inaktive und nicht benötigte Konten sperren",
        "accounts",
        "basic",
        "Verwaiste Konten sind ein häufiger unbemerkter Zugangsweg.",
        ("account_disable_post_pw_expiration", "no_shelllogin_for_systemaccounts"),
        ("anssi", "bsi", "nist"),
        "Kontenbestand und verantwortliche Person regelmäßig abgleichen.",
    ),
    _control(
        "GLB-PRV-001",
        "Direkte Root-Anmeldung beschränken",
        "privileges",
        "basic",
        "Administrative Aktionen sollen nachvollziehbaren persönlichen Konten zugeordnet werden.",
        ("sshd_disable_root_login", "root_path_no_dot", "securetty_root_login_console_only"),
    ),
    _control(
        "GLB-PRV-002",
        "sudo restriktiv konfigurieren und protokollieren",
        "privileges",
        "elevated",
        "Privilegien sollen minimal, zeitlich begrenzt und nachvollziehbar vergeben werden.",
        ("sudo_", "ensure_sudo", "use_pty"),
        ("anssi", "bsi", "nist"),
        "sudoers-Ausnahmen und berechtigte Administratoren manuell prüfen.",
    ),
    _control(
        "GLB-SSH-001",
        "SSH-Root-Login deaktivieren",
        "ssh",
        "basic",
        "Direkte Root-Anmeldung verhindert persönliche Nachvollziehbarkeit.",
        ("sshd_disable_root_login",),
    ),
    _control(
        "GLB-SSH-002",
        "SSH mit sicheren Authentisierungsverfahren betreiben",
        "ssh",
        "elevated",
        "Schlüsselbasierte und zentral verwaltete Zugänge reduzieren Passwortangriffe.",
        (
            "sshd_disable_password_authentication",
            "sshd_enable_pubkey_auth",
            "sshd_set_authentication",
        ),
        ("anssi", "bsi", "nist"),
        "Notfallzugang und Schlüsselverwaltung vor einer Änderung sicherstellen.",
    ),
    _control(
        "GLB-SSH-003",
        "SSH-Sitzungen begrenzen und unnötige Weiterleitungen deaktivieren",
        "ssh",
        "elevated",
        "Inaktive Sitzungen und Weiterleitungen können Zugänge unnötig offenhalten.",
        ("sshd_set_idle_timeout", "sshd_disable_x11_forwarding", "sshd_disable_tcp_forwarding"),
    ),
    _control(
        "GLB-SSH-004",
        "SSH-Kryptografie auf sichere Algorithmen begrenzen",
        "crypto",
        "critical",
        "Veraltete Algorithmen schwächen Vertraulichkeit und Authentizität.",
        ("sshd_use_approved_", "sshd_approved_", "sshd_use_strong_rng"),
    ),
    _control(
        "GLB-FS-001",
        "Kritische Konto- und Authentisierungsdateien schützen",
        "filesystem",
        "basic",
        "Unzulässige Besitzer oder Rechte an passwd, shadow und group gefährden alle Konten.",
        (
            "file_permissions_etc_passwd",
            "file_permissions_etc_shadow",
            "file_permissions_etc_group",
            "file_owner_etc_",
            "file_groupowner_etc_",
        ),
    ),
    _control(
        "GLB-FS-002",
        "Weltweit beschreibbare Dateien und Verzeichnisse absichern",
        "filesystem",
        "basic",
        "Unsichere Schreibrechte ermöglichen Manipulation und Rechteausweitung.",
        (
            "world_writable",
            "dir_perms_world_writable",
            "file_permissions_unauthorized_world_writable",
        ),
    ),
    _control(
        "GLB-FS-003",
        "Temporäre und nicht vertrauenswürdige Dateisysteme beschränken",
        "filesystem",
        "elevated",
        "nodev, nosuid und gegebenenfalls noexec reduzieren Missbrauchsmöglichkeiten.",
        ("mount_option_nodev", "mount_option_nosuid", "mount_option_noexec"),
        ("anssi", "bsi"),
        "Anwendbarkeit von noexec anhand installierter Anwendungen prüfen.",
    ),
    _control(
        "GLB-FS-004",
        "Unzulässige SUID- und SGID-Dateien erkennen",
        "filesystem",
        "critical",
        "Privilegierte Programme müssen auf einen begründeten Mindestbestand beschränkt sein.",
        ("no_suid", "no_sgid", "suid", "sgid"),
        ("anssi", "bsi"),
        "Gefundene Dateien gegen den freigegebenen Sollbestand prüfen.",
    ),
    _control(
        "GLB-KRN-001",
        "Speicherschutz und Kernel-Härtung aktivieren",
        "kernel",
        "basic",
        "ASLR und eingeschränkte Kernelinformationen erschweren Exploitation.",
        ("randomize_va_space", "dmesg_restrict", "kptr_restrict", "yama_ptrace_scope"),
    ),
    _control(
        "GLB-KRN-002",
        "Gefährliche oder nicht benötigte Kernel-Schnittstellen beschränken",
        "kernel",
        "elevated",
        "Unprivilegiertes BPF, Performance-Zugriffe und unbenötigte Module erhöhen die Angriffsfläche.",
        ("unprivileged_bpf_disabled", "perf_event_paranoid", "kernel_module_"),
        ("anssi", "bsi"),
        "Benötigte Dateisystem- und Hardwaremodule vor dem Sperren inventarisieren.",
    ),
    _control(
        "GLB-KRN-003",
        "Mandatory Access Control aktivieren",
        "kernel",
        "elevated",
        "AppArmor oder SELinux begrenzt Auswirkungen kompromittierter Prozesse.",
        ("apparmor", "selinux"),
        ("anssi", "bsi", "nist"),
        "Profile und Ausnahmen müssen zur Serverrolle passen.",
    ),
    _control(
        "GLB-NET-001",
        "Host-Firewall aktivieren und minimal freigeben",
        "network",
        "basic",
        "Nur für die Serverrolle erforderliche Netzwerkzugänge sollen erreichbar sein.",
        ("firewalld", "nftables", "iptables"),
        ("anssi", "bsi", "nist"),
        "Regelsatz und freigegebene Ports gegen die dokumentierte Serverrolle prüfen.",
    ),
    _control(
        "GLB-NET-002",
        "Unsichere IPv4-Weiterleitungen und Redirects deaktivieren",
        "network",
        "basic",
        "Source Routing und ICMP Redirects können Verkehrswege manipulieren.",
        ("accept_redirects", "send_redirects", "accept_source_route"),
    ),
    _control(
        "GLB-NET-003",
        "Netzwerk-Stack gegen Spoofing und SYN-Angriffe härten",
        "network",
        "elevated",
        "Reverse-Path-Filter und SYN-Cookies reduzieren typische Netzwerkangriffe.",
        ("rp_filter", "tcp_syncookies", "log_martians"),
    ),
    _control(
        "GLB-LOG-001",
        "Zentrale und persistente Systemprotokollierung sicherstellen",
        "logging",
        "basic",
        "Sicherheitsereignisse müssen nach Neustarts erhalten und auswertbar sein.",
        ("journald_storage", "rsyslog", "remote_log", "systemd_journal"),
        ("anssi", "bsi", "nist"),
        "Aufbewahrung, Zeitsynchronisation und zentralen Logempfang manuell nachweisen.",
    ),
    _control(
        "GLB-LOG-002",
        "Auditdienst aktivieren und sicherheitsrelevante Änderungen erfassen",
        "logging",
        "elevated",
        "Auditdaten unterstützen Erkennung, Untersuchung und Verantwortlichkeit.",
        ("auditd", "audit_rules_", "audit_rules"),
        ("anssi", "bsi", "nist"),
    ),
    _control(
        "GLB-LOG-003",
        "Manipulation und Verlust von Auditdaten erschweren",
        "logging",
        "critical",
        "Auditkonfiguration und Protokolle benötigen besondere Integritätssicherung.",
        ("audit_rules_immutable", "auditd_data_retention", "auditd_freq"),
    ),
    _control(
        "GLB-INT-001",
        "Dateiintegritätsüberwachung einrichten",
        "integrity",
        "elevated",
        "Unerwartete Änderungen an Systemdateien sollen erkennbar sein.",
        ("aide", "file_integrity"),
        ("anssi", "bsi", "nist"),
        "Alarmierung, Referenzdatenbank und regelmäßige Ausführung kontrollieren.",
    ),
    _control(
        "GLB-CRY-001",
        "Veraltete kryptografische Verfahren deaktivieren",
        "crypto",
        "elevated",
        "Schwache Protokolle, Hashes und Schlüsselgrößen dürfen nicht zugelassen werden.",
        ("crypto_policy", "fips", "disable_weak", "approved_ciphers"),
        ("anssi", "bsi", "nist"),
        "Anwendungskompatibilität und tatsächlich angebotene Protokolle zusätzlich testen.",
    ),
    _control(
        "GLB-OPS-001",
        "Backup und Wiederherstellung regelmäßig testen",
        "operations",
        "basic",
        "Nur getestete Wiederherstellungen bilden eine belastbare Rückfallmöglichkeit.",
        (),
        ("bsi", "nist"),
        "Backupumfang, Offline-Kopie, Verschlüsselung und Restore-Test dokumentieren.",
    ),
    _control(
        "GLB-OPS-002",
        "Änderungs-, Ausnahme- und Notfallverfahren dokumentieren",
        "operations",
        "basic",
        "Härtung benötigt verantwortliche Freigaben, getestete Rückwege und begründete Ausnahmen.",
        (),
        ("bsi", "nist"),
        "Change, Snapshot, Konsolenzugang, Verantwortliche und Ausnahmefrist nachweisen.",
    ),
]


def _matching_results(
    control: dict[str, Any], results: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    patterns = tuple(str(item).lower() for item in control["patterns"])
    if not patterns:
        return []
    return [
        item
        for item in results
        if any(
            pattern in str(item.get("short_id") or item.get("id") or "").lower()
            for pattern in patterns
        )
    ]


def _evaluate_control(control: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    matches = _matching_results(control, results)
    statuses = {str(item.get("status", "")) for item in matches}
    if "fail" in statuses:
        status = "fail"
    elif statuses & {"error", "notchecked", "notselected"}:
        status = "technical_gap"
    elif "pass" in statuses:
        status = "pass"
    elif matches and statuses <= {"notapplicable"}:
        status = "not_applicable"
    elif control["manual"]:
        status = "manual"
    else:
        status = "not_covered"
    failed_rule_ids = [str(item["id"]) for item in matches if item.get("status") == "fail"]
    return {
        **{key: value for key, value in control.items() if key != "patterns"},
        "category_title": BASELINE_CATEGORIES[control["category"]],
        "status": status,
        "matched_rules": matches,
        "matched_rule_ids": [str(item["id"]) for item in matches if item.get("id")],
        "failed_rule_ids": failed_rule_ids,
        "sources": [BASELINE_SOURCES[source] for source in control["sources"]],
    }


def evaluate_general_linux_baseline(
    scan_report: dict[str, Any],
    level: str = "basic",
    categories: list[str] | None = None,
) -> dict[str, Any]:
    if level not in BASELINE_LEVELS:
        raise ValueError("Unbekanntes Baseline-Niveau")
    requested_categories = list(BASELINE_CATEGORIES) if categories is None else categories
    enabled_categories = list(dict.fromkeys(requested_categories))
    invalid_categories = [item for item in enabled_categories if item not in BASELINE_CATEGORIES]
    if invalid_categories:
        raise ValueError("Unbekannte Baseline-Kategorie")
    level_rank = int(BASELINE_LEVELS[level]["rank"])
    results = [item for item in scan_report.get("results", []) if isinstance(item, dict)]
    controls = [
        _evaluate_control(control, results)
        for control in GENERAL_LINUX_CONTROLS
        if BASELINE_LEVELS[control["level"]]["rank"] <= level_rank
        and control["category"] in enabled_categories
    ]
    counts = dict(Counter(item["status"] for item in controls))
    selected_rule_ids = list(
        dict.fromkeys(rule_id for control in controls for rule_id in control["failed_rule_ids"])
    )
    return {
        "schema_version": 1,
        "baseline": "general-linux",
        "title": "Allgemeines Linux-Hardening",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": str(scan_report.get("target", "")),
        "platform": dict(scan_report.get("platform", {})),
        "scan_generated_at": str(scan_report.get("generated_at", "")),
        "data_stream": str(scan_report.get("data_stream", "")),
        "level": level,
        "level_info": BASELINE_LEVELS[level],
        "enabled_categories": enabled_categories,
        "categories": [
            {"id": category, "title": title, "enabled": category in enabled_categories}
            for category, title in BASELINE_CATEGORIES.items()
        ],
        "system_roles": [
            {"id": role_id, **role_info} for role_id, role_info in SYSTEM_ROLES.items()
        ],
        "counts": counts,
        "controls": controls,
        "selected_rule_ids": selected_rule_ids,
        "sources": list(BASELINE_SOURCES.values()),
        "method": (
            "Kuratiertes Mapping allgemeiner Empfehlungen auf Ergebnisse des letzten "
            "OpenSCAP-Full-Scans; keine eigenständige Zertifizierung."
        ),
    }


def _rule_conflicts(rule_ids: list[str]) -> list[dict[str, Any]]:
    opposites = {
        "enabled": "disabled",
        "disabled": "enabled",
        "installed": "removed",
        "removed": "installed",
        "enable": "disable",
        "disable": "enable",
    }
    indexed: dict[tuple[str, str], str] = {}
    conflicts: list[dict[str, Any]] = []
    for rule_id in rule_ids:
        short_id = rule_id.rsplit("_rule_", 1)[-1]
        for suffix, opposite in opposites.items():
            marker = f"_{suffix}"
            if not short_id.endswith(marker):
                continue
            base = short_id.removesuffix(marker)
            opposite_rule = indexed.get((base, opposite))
            if opposite_rule:
                conflicts.append(
                    {
                        "type": "opposite_rules",
                        "severity": "blocking",
                        "rules": [opposite_rule, rule_id],
                        "message": (f"Gegensätzliche Regeln für {base}: {opposite} und {suffix}."),
                    }
                )
            indexed[(base, suffix)] = rule_id
            break
    return conflicts


def build_baseline_hardening_plan(
    baseline: dict[str, Any], role: str, selected_control_ids: list[str]
) -> dict[str, Any]:
    if role not in SYSTEM_ROLES:
        raise ValueError("Unbekannte Systemrolle")
    if not selected_control_ids:
        raise ValueError("Mindestens einen Baseline-Eintrag auswählen")
    unique_ids = list(dict.fromkeys(str(item) for item in selected_control_ids))
    if len(unique_ids) != len(selected_control_ids) or len(unique_ids) > 200:
        raise ValueError("Ungültige oder zu grosse Baseline-Auswahl")
    available = {
        str(item.get("id")): item
        for item in baseline.get("controls", [])
        if isinstance(item, dict) and item.get("id")
    }
    unknown = [control_id for control_id in unique_ids if control_id not in available]
    if unknown:
        raise ValueError("Auswahl enthält Einträge ausserhalb der aktuellen Baseline")

    selected = [available[control_id] for control_id in unique_ids]
    rule_ids = list(
        dict.fromkeys(
            str(rule_id) for control in selected for rule_id in control.get("failed_rule_ids", [])
        )
    )
    role_info = SYSTEM_ROLES[role]
    sensitive = set(role_info["sensitive_categories"])
    reviews = []
    manual_controls = []
    skipped_controls = []
    for control in selected:
        control_id = str(control.get("id"))
        status = str(control.get("status", ""))
        if status in {"manual", "not_covered", "technical_gap"}:
            manual_controls.append(
                {
                    "id": control_id,
                    "title": control.get("title"),
                    "status": status,
                    "reason": control.get("manual")
                    or "Keine vollständig automatisierbare OpenSCAP-Massnahme vorhanden.",
                }
            )
        elif status in {"pass", "not_applicable"}:
            skipped_controls.append(
                {
                    "id": control_id,
                    "title": control.get("title"),
                    "status": status,
                    "reason": ("Bereits bestanden" if status == "pass" else "Nicht anwendbar"),
                }
            )
        if control.get("category") in sensitive and control.get("failed_rule_ids"):
            reviews.append(
                {
                    "type": "role_sensitive",
                    "severity": "review",
                    "control_id": control_id,
                    "message": (
                        f"{control.get('category_title', control.get('category'))} kann die Rolle "
                        f"„{role_info['title']}“ oder den Remotezugang beeinflussen."
                    ),
                }
            )
    conflicts = _rule_conflicts(rule_ids)
    status = "blocked" if conflicts else "review_required" if reviews else "ready"
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": str(baseline.get("target", "")),
        "platform": dict(baseline.get("platform", {})),
        "data_stream": str(baseline.get("data_stream", "")),
        "role": role,
        "role_info": role_info,
        "selected_control_ids": unique_ids,
        "selected_controls": [
            {
                "id": control.get("id"),
                "title": control.get("title"),
                "category": control.get("category"),
                "status": control.get("status"),
                "failed_rule_ids": list(control.get("failed_rule_ids", [])),
            }
            for control in selected
        ],
        "rule_ids": rule_ids,
        "conflicts": conflicts,
        "reviews": reviews,
        "manual_controls": manual_controls,
        "skipped_controls": skipped_controls,
        "counts": {
            "controls": len(selected),
            "actionable_rules": len(rule_ids),
            "manual": len(manual_controls),
            "skipped": len(skipped_controls),
            "conflicts": len(conflicts),
            "reviews": len(reviews),
        },
        "status": status,
        "message": (
            "Blockierende Regelkonflikte müssen zuerst aufgelöst werden."
            if conflicts
            else "Rollenabhängige Hinweise müssen vor der Paketerstellung bestätigt werden."
            if reviews
            else "Auswahl ist technisch bereit für die Paketerstellung."
        ),
    }
