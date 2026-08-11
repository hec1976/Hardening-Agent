# Changelog

## 0.17.0 - 2026-08-11

- Die Hardening-Seite trennt nun sichtbar zwischen offiziellem Hersteller-Benchmark und
  allgemeinem Linux-Hardening nach ANSSI, BSI und NIST.
- Die allgemeine Baseline ist kein verschachtelter Bestandteil des OpenSCAP-Ergebnisses mehr,
  sondern ein eigener Bereich mit Niveau, Kategorien, Systemrolle und Paketerstellung.
- Der Prüfbericht besitzt getrennte Übersichtskarten für Hersteller-Benchmark und allgemeines
  Linux-Hardening. Profil, Datenstrom, Ergebniszahlen und Abdeckung sind sofort sichtbar.
- Der Hersteller-Benchmark-Bericht kann direkt aus seiner Übersichtskarte heruntergeladen werden.
- Das Berichtspaket enthält eindeutig benannte Dateien für Hersteller-Benchmark und allgemeines
  Linux-Hardening sowie eine kurze Inhaltsbeschreibung und SHA-256-Prüfsummen.

## 0.16.1 - 2026-08-11

- Alle `virsh`-Aufrufe erzwingen ein stabiles, nicht lokalisiertes Ausgabeformat. Auf deutschen
  Systemen wurden die übersetzten `dominfo`-Felder zuvor nicht erkannt und deshalb alle Domains
  fälschlich als `unknown` angezeigt.
- IP-Adressen laufender Domains werden dadurch wieder über QEMU Guest Agent, DHCP-Lease und ARP
  ermittelt.
- Die KVM-Tabelle zeigt verständliche deutsche Statusfelder mit klaren Farben: Läuft,
  Ausgeschaltet, Pausiert, Blockiert oder Abgestürzt.
- Bei einer laufenden Domain ohne ermittelbare IP steht ausdrücklich „Nicht erkannt“; echte
  `dominfo`-Fehler erscheinen als Warnung statt stillschweigend als unbekannter Zustand.

## 0.16.0 - 2026-08-11

- Neuer geführter Ablauf „Hardening-Paket in 3 Schritten“: Systemrolle wählen, mehrere
  Baseline-Einträge markieren und die gemeinsame Auswahl prüfen.
- Rollen für allgemeine Server, Mail-, Web- und Datenbankserver, KVM-Hosts sowie Arbeitsstationen
  machen betriebsrelevante Auswirkungen vor dem Export sichtbar.
- Der serverseitige Plan übernimmt ausschließlich aktuell fehlgeschlagene OpenSCAP-Regeln,
  trennt manuelle Punkte und blockiert erkannte gegensätzliche Regelpaare.
- Ein gemeinsames Paket enthält Apply, Verify und einen dateibasierten Restore sowie Richtlinien-,
  Baseline-, Plan- und optional vorhandene KI-Setup-Daten.
- Apply prüft die Paket-Hashes, sichert erkannte Konfigurationsdateien und erfasst den vorherigen
  Paketbestand. Restore prüft ebenfalls die Hashes und stellt die gesicherten Dateien zurück.
- Die technische OpenSCAP-Einzelauswahl und Qwen-Priorisierung liegen nun in einem geschlossenen
  Expertenbereich; der normale Arbeitsablauf bleibt kompakt.

## 0.15.0 - 2026-08-11

- Jeder Eintrag der allgemeinen Linux-Baseline bietet nun „KI-Setup erstellen“ mit einem auf
  Distribution, Version, Prüfstatus, zugeordnete OpenSCAP-Regeln und Referenz-IDs begrenzten
  Qwen-Kontext.
- Setup-Entwürfe enthalten konkrete Sollparameter, Voraussetzungen, Betriebswirkung,
  Validierung, Rücknahme und Warnungen; KI-generierte Shell-Befehle sind ausdrücklich gesperrt.
- Nur serverseitig bestätigte, fehlgeschlagene OpenSCAP-Regeln können aus einem KI-Setup in die
  Hardening-Auswahl übernommen werden. Manuelle und nicht abgedeckte Punkte bleiben
  Betreiberpläne.
- KI-Setups werden pro Ziel und Baseline-Eintrag reproduzierbar als JSON-Bericht gespeichert.
- Qwen-Hardening-Priorisierung ist auf acht kompakte Resultate begrenzt, erhält mehr
  Ausgabetokens und repariert abgeschnittene JSON-Antworten automatisch einmal. Damit wird der
  Fehler „Unterminated string“ nicht mehr unmittelbar an die GUI durchgereicht.

## 0.14.3 - 2026-08-11

- Debian 13 fällt nicht mehr stillschweigend auf den Debian-12-SCAP-Datenstrom zurück; nur ein
  exakt zur Distribution und Hauptversion passender Datenstrom kann Full Scan und Hardening
  freigeben.
- Der Agent kann für Debian 13 den vorgebauten offiziellen ComplianceAsCode-0.1.81-Inhalt laden,
  gegen die veröffentlichte SHA-512-Summe prüfen und ausschließlich `ssg-debian13-ds.xml` auf
  das Ziel übertragen.
- Lokal ergänzte, versionsgenaue Datenströme unter `/usr/local/share/xml/scap/ssg/content` werden
  inventarisiert und sicher für Scan sowie Remediation zugelassen.
- Läufe ohne ein einziges fachlich bewertetes Ergebnis und mit überwiegend `notapplicable` werden
  als inkompatibel gekennzeichnet; daraus wird kein Hardening angeboten.
- Debian-spezifische GUI-Texte erklären Paketlücke, Inhaltsquelle und nächsten Schritt eindeutig.

## 0.14.2 - 2026-08-11

- OpenSCAP-Installation meldet nach dem Paketmanager sofort einen erfolgreichen Abschluss.
- Zeitaufwendige Inventar- und SCAP-Datenstromerkennung ist ein separater, sichtbar
  protokollierter Folgeschritt und blockiert nicht mehr den Installationsstatus.
- Installationsschaltfläche wird bei Erfolg, Berechtigungsbedarf und Fehler zuverlässig wieder
  freigegeben.

## 0.14.1 - 2026-08-11

- Prüfbericht zeigt OpenSCAP-Regeln und allgemeine Linux-Baseline gemeinsam an.
- Filter für Freitext, Prüfart, Status, Kategorie, offizielle Quelle und Maßnahmenauswahl.
- Dynamische Kategorien, sichtbare Trefferanzahl und vollständiges Zurücksetzen aller Filter.
- Baseline-Empfehlungen zeigen Niveau, technische SCAP-Zuordnung, manuelle Ergänzung und
  offizielle Referenzen direkt im Prüfbericht.

## 0.14.0 - 2026-08-11

- Allgemeine Linux-Hardening-Baseline mit ANSSI-BP-028, BSI SYS.1.3 und NIST SP 800-123 als
  nachvollziehbare Einordnung des vorhandenen OpenSCAP-Full-Scans.
- Drei Niveaus, zwölf einzeln aktivierbare Kategorien, Statusfilter und offizielle Referenzen pro
  Empfehlung.
- Klare Trennung zwischen bestanden, fehlgeschlagen, nicht anwendbar, manuell, nicht abgedeckt
  und technischer Prüflücke.
- Fehlgeschlagene zugeordnete SCAP-Regeln lassen sich direkt in die kontrollierte
  Hardening-Auswahl übernehmen.
- Baseline-Bericht wird gespeichert und in Prüf- sowie Maßnahmenpakete aufgenommen.
- Qwen erhält Baseline-Fehlschläge und Referenz-IDs als zusätzlichen Priorisierungskontext;
  technische Status bleiben ausschließlich OpenSCAP-basiert.

## 0.13.2 - 2026-08-11

- XCCDF-Regeln, deren Name `_group_` enthält, werden nicht mehr zusätzlich als Gruppe in ein
  Tailoring aufgenommen. Die Typbestimmung verwendet jetzt den ersten XCCDF-Typmarker.
- Regressionstest für `gid_passwd_group_same`: genau ein eindeutiger `<select>`-Eintrag.

## 0.13.1 - 2026-08-11

- KI-Hardening-Antworten auf höchstens zwölf kompakte Empfehlungen begrenzt, Kontext und Ausgabe
  verkleinert, Modell im Speicher gehalten und Hintergrund-Timeout auf zehn Minuten erhöht.
- Die ausgewählte OpenSCAP-Nachprüfung bewahrt jetzt das Diagnoseprotokoll statt nur einen
  internen Rückgabecode anzuzeigen.
- Vollständige ausgewählte Regelresultate können auch bei einem ungewöhnlichen OpenSCAP-RC
  sicher ausgewertet werden; bei fehlenden Resultaten wird die echte Scannerdiagnose angezeigt.

## 0.13.0 - 2026-08-11

- Qwen priorisiert nach jedem Full Scan echte fehlgeschlagene OpenSCAP-Regeln im Hintergrund.
- Die Analyse bewertet Priorität, Betriebswirkung und anschliessende Validierung und bezieht den
  OVAL-Schwachstellenkontext ein.
- Ein KI-Vorschlag kann kontrolliert in die Profilauswahl übernommen werden; erfundene, doppelte
  oder nicht fehlgeschlagene Regel-IDs werden serverseitig verworfen.
- KI-Analysen werden als reproduzierbarer JSON-Bericht gespeichert. Ausführbare Massnahmen
  stammen weiterhin ausschliesslich aus OpenSCAP.

## 0.12.18 - 2026-08-11

- OVAL `.bz2` and `.gz` feeds are now decompressed and hashed on the agent host
  before upload, so targets no longer require `bzip2` or `gzip` utilities.
- Added a bounded 512 MiB decompressed-feed safety limit and verified the exact
  uploaded XML digest on the target before OpenSCAP evaluation.
- The GUI now explains that `notapplicable` rules were evaluated for
  applicability and are different from `notselected` or `notchecked` gaps.

## 0.12.17 - 2026-08-11

- Full Scan now discovers and selects every XCCDF Group as well as every Rule.
- Fixed the case where explicit rule selections remained `notselected` because
  one or more parent groups were still disabled by benchmark defaults.
- Selected remediation profiles use the same group hierarchy activation before
  selecting only the operator-approved failed rules.

## 0.12.16 - 2026-08-11

- Replaced unreadable grey Full Scan scope cards with solid light surfaces,
  darker text, larger labels and larger checkboxes.
- Full Scan now always renders a dedicated OVAL vulnerability result list,
  including affected, unaffected, unknown and error definitions.
- Added vulnerability filters, CVE/reference and severity display, official feed
  metadata/link and a bounded scrollable result area.

## 0.12.15 - 2026-08-11

- Removed the vendor `standard` profile from the Full Scan execution path.
- Full Scan now discovers every rule ID directly in the selected SCAP data
  stream and builds one independent temporary profile with every rule selected.
- The full profile and selected remediation Tailoring no longer use `extends`,
  preventing hundreds of rules from inheriting `notselected` from `standard`.
- Simplified GUI wording and selection to describe the independent benchmark.

## 0.12.14 - 2026-08-11

- Simplified the primary GUI workflow to system discovery, one Full Scan,
  failed-rule selection, saved Hardening profile and remediation export.
- Removed supplemental-rule actions and the separate vendor-profile scan from
  the normal operator workflow; technical coverage remains visible in reports.
- Fixed OpenSCAP 1.3.6 remediation generation for tailored results by verifying
  the selection first and generating fixes from the same Tailoring plus source
  data stream instead of an unresolved tailored TestResult `--result-id`.

## 0.12.13 - 2026-08-11

- Full benchmark scans no longer discard all useful results when OpenSCAP keeps
  individual rules `notselected` or `notchecked` because of benchmark constraints.
- Reports now distinguish attempted, evaluated and unassessed supplemental rules
  and mark incomplete technical coverage as `partial` instead of failing the job.
- The same transparent partial-result handling is used for manual supplemental scans.

## 0.12.12 - 2026-08-11

- Fixed XCCDF 1.2 Tailoring validation on OpenSCAP 1.3.6 by adding the required
  `time` attribute to each Tailoring version element.
- Selected remediation now explicitly deselects all unchosen benchmark rules
  and selects only the operator-approved failures through a temporary profile.
- Selected Apply, Verify, policy metadata and Tailoring files can be downloaded
  as a ZIP or staged into a private random `/tmp` directory on the target.

## 0.12.11 - 2026-08-11

- Full Scan now expands narrow vendor profiles to the complete distribution
  benchmark through temporary read-only Tailoring batches.
- The GUI explicitly distinguishes the official profile from all benchmark rules.
- Added a one-click "Vollständigen Benchmark prüfen" action after a profile scan.

## 0.12.10 - 2026-08-11

- Supplemental rules outside the vendor profile are now evaluated through a
  temporary XCCDF Tailoring profile instead of `--rule` filtering.
- The tailoring extends the chosen vendor profile and explicitly selects the
  operator's additional rules; it is removed together with all scan temp files.
- `notchecked` remains a valid transparent scan result instead of aborting the run.

## 0.12.9 - 2026-08-11

- Distinguish all benchmark rules from rules actually selected by a profile.
- Added a read-only supplemental scan for operator-selected `notselected` and
  `notchecked` rules; only resulting failures become hardening candidates.
- Preserve and merge supplemental results into the current OpenSCAP report.

## 0.12.8 - 2026-08-11

- Replaced the remaining shell-format dependency for OpenSCAP results with a
  bounded gzip/base64 transfer and Python XML parsing on the agent host.
- XCCDF namespaces and line formatting no longer affect result extraction.
- Added strict compressed/decompressed size limits and malformed-data handling.

## 0.12.7 - 2026-08-11

- Fixed empty OpenSCAP scan results on openSUSE by always writing an XCCDF
  result file and parsing its `rule-result` elements deterministically.
- Console progress parsing remains as a compatibility fallback and title source.
- Temporary result and log files are removed after every scan.

## 0.12.6 - 2026-08-11

- Increased operational text sizes and contrast throughout the light workspace.
- Replaced low-contrast grey helper text with darker readable text.
- Error messages in the dark activity log now use white text on a red panel;
  successful messages use dark text on a light green panel.
- Improved warning, scanner, SCAP-result, source, and report readability.

## 0.12.5 - 2026-08-11

- Fixed SCAP profile discovery by reading packaged profile IDs directly from
  each data-stream XML instead of depending on `oscap info` output formatting.
- Associated sampled rules and profiles with their originating data stream.
- Prefer the distribution/version-specific stream; openSUSE now uses only
  `ssg-opensuse-ds.xml` instead of mixing SLES, SLE Micro, and old SLE streams.

## 0.12.4 - 2026-08-11

- Removed manual categories from manufacturer-source editing and source cards.
- Source mappings now contain only provenance and version applicability; rule
  categories shown after a scan are derived from the actual SCAP results.
- Empty category metadata is accepted for manually assigned documentation sources.

## 0.12.3 - 2026-08-11

- Removed the obsolete system-role selector from the GUI and every scan API.
- Full scans are now scoped exclusively by the detected distribution/version,
  selected SCAP data stream, and official OpenSCAP profile.
- Removed the role field from newly generated full-scan reports.

## 0.12.2 - 2026-08-11

- Added a safe GUI restart launcher that stops only a same-user process verified
  as `hardening-agent gui` on the selected port.
- Prevents an older background GUI from continuing to serve removed interface content.

## 0.12.1 - 2026-08-11

- Rebuilt **Prüfumfang & Quellen** around explicit OpenSCAP, OVAL and manufacturer
  documentation provenance.
- Source cards now show distribution, version pattern, review date, origin,
  scope and mapped categories in a readable management view.
- Increased policy-page contrast, link visibility and operational font sizes.

## 0.12.0 - 2026-08-11

- Removed the bundled fixed-size agent rule catalog, its editor, CLI commands,
  API routes, policy engine and deterministic bundle generator completely.
- The only configuration-hardening workflow now scans every rule in the selected
  installed OpenSCAP/vendor profile.
- Added downloadable HTML/JSON scan reports with checksums and selected-rule markings.
- Kept per-rule remediation selection, reusable selection profiles and fresh
  selected-rule rescans before OpenSCAP fix generation.

## 0.11.0 - 2026-08-11

- Replaced the 23-rule add-on workflow as the main GUI path with the complete
  installed OpenSCAP/vendor profile. The legacy agent catalog remains hidden for
  backwards compatibility and is not part of the default scan.
- Full manufacturer scans now retain the real OpenSCAP rule titles and expose
  every open/failed rule as an individual checkbox grouped by security topic.
- Operators can select failed rules, save that selection as a reusable named
  profile, and load it again for the same base profile and data stream.
- Selected package generation rescans only the chosen rules with repeated
  `oscap xccdf eval --rule` arguments and generates Bash remediation from that
  fresh result file. Passed or stale rules cannot be smuggled into the package.
- Generated packages verify exactly the selected rules and retain profile,
  data-stream, selected-rule, source, and scan metadata.

## 0.10.0 - 2026-08-11

- Added a visible background **Full Scan** that combines the selected native
  XCCDF/OpenSCAP profile, official OVAL vulnerability/patch evaluation, and the
  curated agent add-on checks without depending on Qwen.
- Added official feed selection for openSUSE Leap 15.x, Debian 12/13, and Ubuntu
  releases. Unsupported or ambiguous product streams are reported instead of
  silently using a related distribution's feed.
- OVAL results use the distinct states `affected`, `not_affected`, `unknown`,
  and `error`; OVAL `true` is never displayed as a passed compliance check.
- Feeds are downloaded only by the agent, restricted to official HTTPS hosts,
  size-limited, hashed, cached with provenance metadata, and transferred using
  local copy, SCP, or Vagrant upload instead of a base64 command payload.
- Full scan progress is pollable, survives an individual unsupported OVAL
  provider, and writes a private combined JSON report below the agent data home.

## 0.9.0 - 2026-08-11

- Reworked the GUI policy model into four explicit layers: versioned vendor
  documents, machine-readable OpenSCAP policy/profile, executed full-profile
  audit, and the small curated agent add-on catalog.
- Renamed generic "Hardening controls" labels to "Agent controls" so the 23
  curated rules are no longer presented as complete SUSE/CIS/STIG hardening.
- Added generation of a complete native remediation package from the exact
  installed OpenSCAP profile after its full audit. The package contains the
  generated Bash fixes, verification scan, policy metadata, README, and hashes.
- Native packages require a second explicit confirmation at execution time,
  refuse non-root execution, warn about authentication/network/boot impact, and
  state clearly that no general automatic rollback exists.
- OpenSCAP profiles are now associated with their actual data stream, preventing
  a profile from accidentally being evaluated against another installed stream.
- Expanded guideline discovery scopes to the selected target, a manually entered
  distribution/version, all saved inventory versions, or all supported vendors.
  Broad searches never preapprove a wildcard version; the operator must enter
  and verify the applicable version before saving a candidate.

## 0.8.0 - 2026-08-11

- Added an explicit operator-triggered online search for new official hardening
  guidelines based on the selected target distribution and version.
- Search results are restricted to fixed HTTPS vendor-domain allowlists for
  SUSE/openSUSE, Debian, Ubuntu, RHEL, Rocky, AlmaLinux, and Oracle Linux.
- Qwen reviews only the allowlisted result metadata, references candidates by
  validated list index, and cannot add URLs or activate sources by itself.
- Candidates remain separate from trusted sources. **Als Quellenkandidat
  übernehmen** fills the friendly source form; an operator must still inspect,
  categorise, version, enable, and save the source.
- Online access occurs only after an explicit confirmation and never during the
  normal audit, OpenSCAP scan, package generation, or scheduled background work.

## 0.7.0 - 2026-08-11

- Added a friendly manufacturer-source manager for distribution, version
  pattern, official HTTPS URL, review date, scope, categories, and enabled state.
- Built-in source mappings can be copied into an operator-owned override,
  adjusted or disabled without modifying packaged application data.
- Added a Qwen source-coverage review. The model receives only configured
  metadata and deterministic gaps, may suggest official-vendor search terms,
  and cannot invent or automatically approve URLs or executable controls.
- Grouped internal and OpenSCAP checks by hardening category. Operators can
  enable or disable a complete internal category or each individual control.
- Source coverage and technical control coverage remain separate, preventing a
  broad documentation link from being misreported as an executed check.

## 0.6.0 - 2026-08-11

- Integrated detected OpenSCAP profiles as real read-only target checks instead
  of displaying only policy, profile, and rule counts.
- Operators can select an inventoried profile and data stream in the GUI. Both
  values are checked against the target inventory before execution.
- Every parsed SCAP rule result is included in the common GUI report with its
  profile, data stream, status, and mapped official vendor-guideline sources.
- Coverage is recalculated from both the reviewed agent catalog and the executed
  SCAP profile, so the remaining-gap list reflects native policy checks.
- OpenSCAP reports are persisted as private JSON files below the operator data
  directory. Scans never use OpenSCAP remediation mode.

## 0.5.1 - 2026-08-11

- Added an explicit GUI action to install OpenSCAP and the distribution-specific
  SCAP content when the guided target check finds them missing.
- Installation uses a fixed package allowlist selected from the detected target
  distribution, requires an operator confirmation, and never accepts package
  names or shell commands from the browser or Qwen.
- Passwordless/root Vagrant targets can install directly. Hosts requiring an
  interactive `sudo` or `su` password receive a copyable vendor-specific command;
  credentials are never collected by the GUI.
- Scanner and policy-content readiness are checked separately, so an `oscap`
  binary without a compatible data stream is no longer reported as ready.

## 0.5.0 - 2026-08-11

- Replaced the technical-first hardening form with a guided system check that
  clearly separates target selection, OS/vendor detection, guideline mapping,
  read-only checks, and reviewed package generation.
- Added a visible guideline status for SUSE/openSUSE, Debian/Ubuntu, and the
  RHEL family with official vendor documents, version-applicability warnings,
  native compliance framework, and installation guidance.
- Inventory now detects OpenSCAP/USG, installed SCAP data streams, rule/profile
  counts, available profile IDs, and a bounded sample of machine-readable rule
  IDs without changing the target.
- The GUI now states explicitly when the built-in catalog is only a partial
  check, shows uncovered hardening topics, and compares its scope with native
  SCAP content instead of implying that 23 controls are complete hardening.
- Moved manual JSON editing into a collapsed expert area. Qwen continues to
  prioritize reviewed findings but cannot silently invent or activate new
  executable controls.

## 0.4.0 - 2026-08-11

- Added a GUI rule workshop for creating, copying, importing, editing, deleting,
  and exporting custom hardening controls.
- Custom rules are stored separately under the operator data directory and
  survive application updates.
- Added mandatory pre-save validation for schema fields, IDs, parameters,
  placeholders, dependencies, conflicts, duplicate IDs, HTTPS source metadata,
  Bash syntax, read-only audit/verification commands, and unsafe remediation
  patterns.
- Custom rules are loaded by the same deterministic audit, planning, reporting,
  and bundle-generation path as bundled controls. Technical validation remains
  separate from mandatory human review of guideline applicability and test-VM
  results.

## 0.3.21 - 2026-08-11

- Added a dedicated audit report view that links each real system result to its
  current configuration evidence, audit command, expected verification, status,
  and official guideline publisher/reference/version/review date.
- Added report filtering and preserved the report across ordinary status and
  target-list refreshes; actual target edits still invalidate stale results.
- Reduced the entire UI to a denser admin-console scale, including sidebar,
  headings, hero, metrics, workflow, panels, inputs, model rows, and buttons.

## 0.3.20 - 2026-08-11

- Refined the light GUI into a denser security console layout with smaller page
  and hero titles, tighter cards, panels, controls, and navigation spacing.
- Tool health now fits into one five-column row on wide screens, eliminating the
  large empty area caused by the wrapped Vagrant card.
- Improved responsive layouts for tool status and model selection.
- All visible German GUI copy now follows Swiss orthography and uses `ss`
  instead of `ß`.

## 0.3.19 - 2026-08-11

- Installed Ollama models can be selected directly in the GUI. The browser
  remembers the selected model and restores it on the next GUI start.
- The AI card and model panel now distinguish Ready, Analyzing, Error, and
  Unavailable states with a visible detail message and animated activity dot.
- The local installer interactively offers qwen3:8b, qwen3:14b, both, or no
  model download. The 8B model is recommended by default for 8 GB VRAM.
- Non-interactive installation never downloads a model implicitly; optional
  automation can set `LHA_INSTALL_MODELS` to `none` or a comma-separated list.

## 0.3.18 - 2026-08-11

- Deterministic Linux checks now return to the GUI immediately without waiting
  for Qwen.
- Optional Qwen analysis runs in a daemon background job with a polled status;
  the GUI stays usable and applies the recommendation only when it completes.
- Background recommendations have a five-minute total limit. Failure or timeout
  leaves the visible check results and profile selection untouched.

## 0.3.17 - 2026-08-11

- Ollama recommendations now use streaming NDJSON so a long-running local 14B
  generation sends data continuously instead of hitting the socket timeout
  while `stream: false` produces no response bytes.
- Added `/no_think` as a Qwen3 compatibility fallback alongside the native
  `think: false` API field.
- Reduced the recommendation context to 4096 tokens and capped output at 768
  tokens; deterministic Linux check evidence remains complete locally.

## 0.3.16 - 2026-08-11

- Qwen recommendations now disable thinking output, use an 8192-token context,
  cap generation at 1536 tokens, and keep the loaded Ollama model warm for ten
  minutes.
- Inventory evidence sent to Qwen is capped per section to reduce prompt
  evaluation time while the complete evidence remains available to local
  deterministic checks.
- The GUI limits recommendation waiting to 120 seconds and then safely retains
  the profile defaults and completed check results.

## 0.3.15 - 2026-08-11

- Loading applicable controls now performs their real read-only audit and
  verification commands on the target in one transport session.
- Every control reports Passed, Failed, Manual, or Error with captured audit
  and verification evidence in the GUI.
- The activity log includes a result summary instead of merely saying that
  controls were loaded.
- Browser disconnects while a long request finishes no longer produce a second
  response attempt and a `BrokenPipeError` traceback.

## 0.3.14 - 2026-08-11

- Vagrant/libvirt projects are now discovered directly from bounded provider
  state under `/mnt/data/vms/*/.vagrant/machines/*/libvirt`, independently of
  the per-user `vagrant global-status` cache.
- Provider IDs and conventional libvirt domain names are matched to the KVM
  inventory before a target is saved or audited, preventing Vagrant guests from
  silently falling back to generic SSH.

## 0.3.13 - 2026-08-11

- Root-owned Vagrant keys now execute `vagrant ssh` with root's HOME and
  VAGRANT_HOME, matching a successful manual root invocation in the project
  directory. Operator Vagrant metadata discovery remains isolated under the
  original desktop user.
- The launcher no longer leaks the operator VAGRANT_HOME into the root GUI.
- The installed agent version is visible in the GUI sidebar and HTTP server
  identification. Audit activity explicitly states when Vagrant CLI is used.

## 0.3.12 - 2026-08-11

- The root GUI launcher now passes the original operator identity explicitly.
- In root mode, Vagrant discovery runs `global-status` as that operator through
  `runuser`, preserving their HOME and VAGRANT_HOME, while connection execution
  remains in the root process for intentionally root-owned keys.
- Vagrant commands also receive the operator HOME internally; no shell exports
  or manual commands are required.

## 0.3.11 - 2026-08-11

- Vagrant transport no longer depends on a previously saved `vm_name` field.
- Before every audit, a target is automatically linked to a Vagrant/libvirt
  domain by exact target/domain name or, when unambiguous, its guest IP address.
- Existing targets named like `opensuse15_default` are upgraded in place to
  native Vagrant transport and QEMU Guest Agent fallback before connecting.

## 0.3.10 - 2026-08-10

- Added an automatic read-only QEMU Guest Agent fallback for Vagrant targets
  whose SSH authentication is rejected.
- Guest scripts are passed through QGA `guest-exec` using base64-encoded stdin;
  exit status, stdout, stderr, truncation, invalid responses, and timeouts are
  handled explicitly.
- The GUI reports successful QEMU Guest Agent fallback without requiring users
  to export variables, enter passwords, or change Vagrant key ownership.

## 0.3.9 - 2026-08-10

- Vagrant targets now execute read-only inventory scripts through the native
  `vagrant ssh <machine> -c` transport instead of reconstructing a generic SSH
  command from a subset of `vagrant ssh-config`.
- Saved Vagrant targets retain project directory, machine name, and Vagrant home
  so all provider-specific SSH behavior remains authoritative.
- Ordinary SSH, local, and non-Vagrant KVM targets keep their existing transport.
- No Vagrant key ownership or permissions are changed.

## 0.3.8 - 2026-08-10

- Replaced Vagrant key repair with a non-mutating execution-mode check. The
  setup never changes key ownership or permissions.
- Added `scripts/start-gui.sh`: it runs normally for operator-owned keys and
  invokes the GUI through `su` with the operator's Vagrant index when keys are
  intentionally root-owned.
- Missing keys, mixed ownership, and unsupported permissions stop with a clear
  diagnostic instead of modifying the existing Vagrant environment.

## 0.3.7 - 2026-08-10

- The local installer now checks every Vagrant/libvirt private key belonging to
  the operator's Vagrant index.
- When a key has root ownership or unsafe permissions, the interactive setup
  offers a one-time `su` repair and then verifies ownership again as the normal
  operator user.
- The repair is deliberately limited to detected `private_key` files: it does
  not recursively change project ownership or touch VM disks.
- Added the `hardening-agent vagrant-access` diagnostic/repair command.

## 0.3.6 - 2026-08-10

- Root GUI mode now discovers Vagrant environments stored in regular users'
  `.vagrant.d` directories without requiring a manual `VAGRANT_HOME` export.
- Added a one-click **Vagrant-Ziel einrichten** action that resolves and saves
  host, user, port, managed private key, and KVM domain as one complete target.
- Managed systems now show whether an SSH key is configured, making incomplete
  profiles immediately visible.

## 0.3.5 - 2026-08-10

- Vagrant-managed KVM targets now refresh host, SSH user, port, and the exact
  managed private key from `vagrant ssh-config` before audit, control discovery,
  and bundle generation.
- Existing targets with stale or missing Vagrant connection values are repaired
  and saved automatically; ordinary KVM and SSH targets remain unchanged.
- The activity log explicitly reports when the Vagrant SSH connection was fixed.

## 0.3.4 - 2026-08-10

- Added target deletion to **Verwaltete Systeme**, including a clear confirmation
  prompt and immediate refresh of target lists and status counters.
- Deleting a target removes only its saved connection definition. Existing audit
  inventories and generated hardening bundles remain available.

## 0.3.3 - 2026-08-10

- Added explicit GUI editing for saved local, SSH, KVM, and Vagrant targets.
- The editor restores all connection values, clearly marks edit mode, and can be
  cancelled without changing the stored target.
- Target renames are atomic and refuse to overwrite another existing target or
  recreate a target that was removed while the form was open.

## 0.3.2 - 2026-08-10

- Added automatic correlation of local libvirt domains with Vagrant
  `global-status`, using provider UUID and conventional domain-name matching.
- Added an explicit **Vagrant übernehmen** action that reads the exact host,
  user, port, and managed identity file from `vagrant ssh-config`.
- Vagrant's relaxed host-key and other SSH options are deliberately not copied;
  the agent retains its own strict SSH security policy.
- Removed the misleading default `~/.ssh/hardening-agent` identity path from the
  target form and added Vagrant to GUI/CLI prerequisite status.
- SSH now fails early with a clear missing-key message and uses
  `IdentitiesOnly=yes` so the exact selected Vagrant or operator key is used.

## 0.3.1 - 2026-08-10

- Reworked the GUI into a higher-contrast light workspace with a dark navigation
  rail, clearer visual hierarchy, and more distinct panels.
- Reduced page titles, hero copy, metrics, buttons, navigation, spacing, and
  panel density so more controls remain readable on one screen.
- Improved text, input, table, detail, source, and selection contrast.

## 0.3.0 - 2026-08-10

- Added a read-only control preview that detects the target distribution before
  showing only profile-, role-, and platform-applicable controls.
- Added authoritative per-control selection in the GUI. Operator selection
  overrides AI rule choice while dependency and conflict validation remain active.
- Qwen can provide a visible initial checkbox recommendation and rationale;
  the operator's reviewed selection remains authoritative for bundle generation.
- Expanded every control with audit, remediation, verification, rollback,
  platform, risk, dependency, publisher, document, reference, version, review
  date, and direct official-source details.
- Added source/reference and severity filtering in both selection and catalog views.

## 0.2.1 - 2026-08-10

- Redesigned the local GUI as a clearer responsive security console with guided
  workflow, improved status cards, target-mode selection, and empty states.
- Added explicit Local Linux and SSH Server target cards while retaining KVM as
  an optional integration.
- The local installer now upgrades `pip`, `setuptools`, and `wheel` inside the
  virtual environment before installing the agent.

## 0.2.0 - 2026-08-10

- Added a local web GUI for targets, audits, profiles, catalog inspection, and
  downloadable execution bundles.
- Added automatic KVM domain, state, resource, and guest-address discovery with
  guest-agent, DHCP lease, and ARP fallbacks.
- Made KVM entirely optional in the GUI, with explicit local-host and ordinary
  SSH target modes and graceful operation when `virsh` is unavailable.
- Added Ollama status, installed-model display, and an explicit model pull action.
- Added an optional conservative Ollama service profile for a single 14B model
  on an 8 GB GPU with CPU/RAM offload.
- Added a Debian bootstrap flow for `sudo` and plain `su`, including root `PATH`
  repair, optional Ollama installation, model pull, NVIDIA reporting, and libvirt
  operator permissions.
- Added a hardened systemd user service and default refusal to run the GUI as root.
- Expanded validation and automated tests for targets, KVM parsing, and GUI assets.

## 0.1.0 - 2026-07-28

- Initial local Ollama/Qwen advisor.
- Deterministic multi-distribution rule selection and bundle generation.
- Read-only SSH/local inventory collection.
- Bash preflight, apply, verification, and rollback bundles.
- KVM snapshot command generation.
- Starter controls for SUSE/openSUSE, Debian, Ubuntu, RHEL, Rocky, and AlmaLinux.
