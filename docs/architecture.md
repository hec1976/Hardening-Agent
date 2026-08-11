# Architecture

## Components

### CLI and local web GUI

The CLI manages targets, inventories, diagnostics and GUI startup. The local
standard-library web server exposes the complete scan workflow on loopback.
Mutating requests and downloads require a random per-process token. Root and
non-loopback operation are refused unless explicitly overridden.

### Transport and target inventory

Local targets use a local shell, SSH targets use the system OpenSSH client, and
Vagrant targets use the Vagrant CLI in the detected project directory. The
collector runs a static read-only inventory script and records platform,
services, networking, mounts, SSH, LSM, audit, sysctl, updates and installed
compliance tooling.

### OpenSCAP/XCCDF engine

The inventory discovers installed data streams and profiles. Full Scan reads
all rule IDs directly from the selected data stream and creates an independent
temporary XCCDF profile that selects every rule. It does not extend the vendor
`standard` profile. Status, title, rule ID and category are stored in a private
JSON report. Exit code 2 is a completed scan containing failed rules.

Failed rules can be selected individually and saved as a reusable selection
profile. Selective remediation explicitly deselects every unchosen benchmark
rule in a temporary Tailoring profile, scans the approved selection again, and
asks OpenSCAP to generate Bash fixes from that result ID. The agent packages but
never executes the generated script automatically.

### OVAL vulnerability engine

Official distribution-specific vulnerability feeds are cached on the agent
host, hashed and evaluated on the target. OVAL vulnerability result `true`
means affected and is intentionally not displayed as XCCDF `pass`.

### Guideline sources and Ollama

Official source mappings include publisher, distribution, version pattern,
review date and categories. Online discovery accepts only HTTPS results from a
distribution-specific vendor allowlist. Qwen may summarize source coverage and
rank candidates; it cannot create executable controls or run privileged code.

### General Linux baseline

The general baseline is a deterministic interpretation layer over the latest Full Scan. A curated
catalog maps cross-distribution ANSSI BP-028, BSI SYS.1.3 and NIST SP 800-123 recommendations to
matching XCCDF rule IDs. It never replaces or changes the scanner result. Controls are reported as
pass, fail, not applicable, manual, not covered or technical gap. Levels and categories can be
selected independently. Qwen receives failed baseline mappings as context, but only OpenSCAP
evidence determines technical status.

### Reports and packages

The report package contains HTML, JSON, the saved general Linux baseline and SHA-256 checksums. A selective
remediation package includes the chosen rule IDs, original scan evidence,
temporary Tailoring, OpenSCAP-generated fix, verification script and checksums.
It can be downloaded or uploaded into a private random `/tmp` directory on the
target. Uploading does not execute it; the GUI displays the explicit Apply and
Verify commands.

## Data flow

```text
target -> read-only inventory -> discovered vendor profile -> full OpenSCAP scan
       -> general Linux baseline mapping -> operator selects failed rules -> saved selection profile
       -> fresh selected-rule scan -> OpenSCAP fix generation -> reviewable ZIP
```

## Privileges

The GUI itself does not require root. Some OpenSCAP reads and all remediation
need privileges on the target. Those operations require explicit confirmation.
Snapshot/backup and console access remain the rollback boundary.
