# Linux Hardening Agent

Lokale Weboberfläche für vollständige Linux-Compliance-Prüfungen mit OpenSCAP/XCCDF,
offiziellen OVAL-Schwachstellenfeeds und einer lokalen Risiko-Priorisierung durch Ollama/Qwen.

Der Agent besitzt keinen eigenen festen Hardening-Regelkatalog. Der Prüfumfang stammt aus dem
zur erkannten Distribution und Hauptversion passenden SCAP-Datenstrom. Der Full Scan erstellt
daraus ein unabhängiges Vollprofil und versucht alle Regeln des Benchmarks auszuwerten.

Status: Alpha (Version 0.17.0). Kein Zertifizierungsprodukt, siehe [Sicherheit](#sicherheit).

## Architektur

[#architektur](#architektur)

- **CLI und lokale Web-GUI:** Die CLI verwaltet Ziele, Inventare, Diagnose und GUI-Start. Der
  eingebaute Webserver (Python-Standardbibliothek) stellt den kompletten Scan-Ablauf nur auf
  Loopback bereit. Verändernde Aufrufe und Downloads benötigen ein zufälliges, pro Prozess
  erzeugtes Token. Root-Betrieb und Nicht-Loopback-Bindung werden ohne explizite Option verweigert.
- **Transport und Ziel-Inventar:** lokale Ziele laufen über eine lokale Shell, SSH-Ziele über den
  System-OpenSSH-Client, Vagrant-Ziele über die Vagrant-CLI im erkannten Projektverzeichnis. Der
  Collector führt ein statisches, read-only Inventar-Skript aus und erfasst Plattform, Dienste,
  Netzwerk, Mounts, SSH, LSM, Audit, Sysctl, Updates und installierte Compliance-Werkzeuge.
- **OpenSCAP/XCCDF-Engine:** die Inventur erkennt installierte Datenströme und Profile. Der Full
  Scan liest alle Regel-IDs direkt aus dem gewählten Datenstrom und erzeugt daraus ein
  unabhängiges, temporäres XCCDF-Profil, das jede Regel auswählt, statt das Vendor-Profil
  `standard` zu erweitern. Ausgewählte fehlgeschlagene Regeln werden als wiederverwendbares
  Auswahlprofil gespeichert; die selektive Remediation deselektiert in einem temporären
  Tailoring-Profil explizit jede nicht gewählte Regel, scannt die freigegebene Auswahl erneut und
  lässt OpenSCAP daraus Bash-Fixes generieren. Der Agent verpackt das generierte Skript, führt es
  aber nie automatisch aus.
- **OVAL-Schwachstellen-Engine:** offizielle, distributionsspezifische Vulnerability-Feeds werden
  auf dem Agent-Host zwischengespeichert, gehasht und auf dem Ziel ausgewertet. Ein OVAL-Ergebnis
  `true` bedeutet betroffen und wird bewusst nicht wie ein XCCDF `pass` dargestellt.
- **Leitfaden-Quellen und Ollama:** offizielle Quellzuordnungen enthalten Herausgeber,
  Distribution, Versionsmuster, Prüfdatum und Kategorie. Die Online-Erkennung akzeptiert nur
  HTTPS-Treffer aus einer distributionsspezifischen Vendor-Allowlist. Qwen darf Quellenabdeckung
  zusammenfassen und Kandidaten einordnen, aber keine ausführbaren Regeln erzeugen oder
  privilegierten Code ausführen.
- **Allgemeine Linux-Baseline:** eine deterministische Interpretationsschicht über dem letzten
  Full Scan. Ein kuratierter Katalog bildet distributionsübergreifende Empfehlungen aus ANSSI
  BP-028, BSI SYS.1.3 und NIST SP 800-123 auf passende XCCDF-Regel-IDs ab, ohne das Scanner-
  Ergebnis zu ersetzen oder zu verändern.
- **Berichte und Pakete:** das Berichtspaket enthält HTML, JSON, die gespeicherte allgemeine
  Baseline und SHA-256-Prüfsummen. Ein selektives Remediation-Paket enthält die gewählten
  Regel-IDs, den ursprünglichen Scan-Beleg, das temporäre Tailoring, den OpenSCAP-generierten Fix,
  ein Verify-Skript und Prüfsummen. Es kann heruntergeladen oder in ein privates, zufällig
  benanntes `/tmp`-Verzeichnis auf dem Ziel hochgeladen werden; das Hochladen führt nichts aus,
  die GUI zeigt die expliziten Apply- und Verify-Befehle an.

Datenfluss:

```text
Ziel -> read-only Inventar -> erkanntes Vendor-Profil -> vollständiger OpenSCAP-Scan
     -> allgemeine Linux-Baseline-Zuordnung -> Betreiber wählt fehlgeschlagene Regeln
     -> gespeichertes Auswahlprofil -> frischer Scan der Auswahl -> OpenSCAP-Fix-Generierung
     -> prüfbares ZIP
```

Die GUI selbst benötigt kein Root. Manche OpenSCAP-Lesevorgänge und jede Remediation brauchen
Rechte auf dem Ziel; diese Vorgänge verlangen eine ausdrückliche Bestätigung. Snapshot/Backup und
Konsolenzugang bleiben die Rollback-Grenze.

Ausführliche Fassung: [`docs/architecture.md`](docs/architecture.md).

## Bedrohungsmodell

[#bedrohungsmodell](#bedrohungsmodell)

**Geschützte Werte:** Verfügbarkeit und administrativer Zugriff auf das Zielsystem, SSH-
Schlüssel und Zugangsdaten, Systemkonfiguration und Prüfnachweise, Integrität der erzeugten
Remediation-Pakete, autoritative Hersteller-Policy- und Quellzuordnung.

**Hauptbedrohungen:** Prompt-Injection über Hostnamen, Banner, Logs oder Konfiguration;
Halluzination des Sprachmodells; Command-Injection über Parameter; manipulierte SCAP-Inhalte,
Berichte oder generierte Pakete; bösartige Substitution des SSH-Hosts; Aussperren eines
Remote-Administrators; unvollständiges Rollback; Geheimnisse, die in Prompts oder Logs gelangen;
Browser-Anfragen, die eine privilegierte oder remote erreichbare GUI treffen.

**Massnahmen:** Das Inventar gilt als nicht vertrauenswürdige Eingabe. Modellausgaben sind auf
Quellenprüfung und Kandidatenreihung beschränkt. Ausgewählte Remediation-IDs werden erneut gegen
die aktuellsten fehlgeschlagenen Scan-Ergebnisse geprüft. Die Remediation-Shell wird von der
installierten OpenSCAP-Policy aus einem frischen Ergebnis erzeugt. SSH-Host-Keys werden geprüft.
Root-Ausführung ist separat und explizit. Datei-Backups und Verify-Skripte werden generiert.
Paket-Prüfsummen erkennen nachträgliche, unbeabsichtigte Änderungen. Die GUI bindet standardmässig
an Loopback, verweigert Root, validiert lokale Host-Header, verlangt ein pro-Prozess-Token für
verändernde Aufrufe und Downloads, begrenzt Anfragegrössen und besitzt keinen Endpunkt, der
Hardening direkt anwendet.

**Restrisiken:** Herstellerinhalte oder generierte Remediation können weiterhin einen
Implementierungsfehler enthalten. Distributions-Updates können das Konfigurationsverhalten
ändern. Paketinstallationen lassen sich durch Datei-Wiederherstellung nicht vollständig
rückgängig machen. KVM-Snapshots können bei aktiven Anwendungen inkonsistent sein. Ein lokaler
Angreifer mit Kontrolle über Repository oder Python-Umgebung kann generierte Ausgaben verändern.
SHA-256-Prüfsummen sind Integritäts-, keine Signaturhilfen. Die GUI besitzt keine
Konto-Authentifizierung und kein TLS und ist nicht für direkte Netzwerk-Exposition gedacht.

Für Produktivbetrieb: Releases signieren, SCAP-Pakete verifizieren, von einem dedizierten
Verwaltungshost aus betreiben und eine unabhängige Konfigurations-/Compliance-Prüfung einsetzen.

Ausführliche Fassung: [`docs/threat-model.md`](docs/threat-model.md).

## Arbeitsablauf

[#arbeitsablauf](#arbeitsablauf)

1. Lokales, SSH- oder Vagrant/KVM-Ziel hinzufügen.
2. Betriebssystem und verfügbare OpenSCAP-Datenströme erkennen.
3. Den exakt passenden Datenstrom vollständig read-only scannen.
4. Ergebnisse gegen die allgemeine Linux-Baseline aus ANSSI, BSI und NIST einordnen.
5. Systemrolle wählen und die gewünschten offenen Baseline-Einträge markieren.
6. Die gemeinsame Auswahl auf Regelkonflikte und betriebliche Risiken prüfen.
7. Ein Paket mit Apply, Verify und Restore herunterladen oder nach `/tmp` des Ziels übertragen.
8. Für einzelne Baseline-Einträge optional einen distributionsbezogenen KI-Setup-Entwurf öffnen.

Der normale Ablauf ist bewusst auf diese drei Entscheidungen reduziert: Rolle, Auswahl und
Paket. Die technische OpenSCAP-Einzelauswahl und Qwen-Priorisierung bleiben in einem
geschlossenen Expertenbereich verfügbar.

Die Hardening-Seite zeigt zwei fachlich getrennte Ebenen:

- **Hersteller-Benchmark:** vollständige maschinenlesbare OpenSCAP-/XCCDF-Prüfung der erkannten
  Distribution und Version.
- **Allgemeines Linux-Hardening:** separate Einordnung derselben technischen Ergebnisse nach
  ANSSI, BSI und NIST mit Systemrolle und kontrollierter Paketerstellung.

Der Prüfbericht stellt beide Ebenen getrennt dar. Das heruntergeladene Berichtspaket enthält den
vollständigen Hersteller-Benchmark als HTML und JSON sowie die allgemeine Linux-Einordnung als
separate JSON-Datei.

Das Massnahmenpaket wird aus einem frischen OpenSCAP-Ergebnis nur für die ausgewählten Regeln
erzeugt. Nach dem Full Scan priorisiert Qwen im Hintergrund ausschliesslich echte fehlgeschlagene
OpenSCAP-Regeln und berücksichtigt den OVAL-Schwachstellenkontext. Der Vorschlag kann mit einem
Klick in die Auswahl übernommen werden, muss aber vom Betreiber geprüft werden. Regel-IDs werden
serverseitig gegen den Scan abgeglichen. Qwen führt keine Root-Befehle aus und erzeugt keine
ausführbaren Regeln; Apply- und Verify-Skripte stammen weiterhin aus OpenSCAP.

Pro Baseline-Eintrag kann Qwen einen kompakten Setup-Entwurf mit Sollwerten, Voraussetzungen,
Betriebswirkung, Validierung und Rücknahme erstellen. Bei einem echten OpenSCAP-Fehlschlag kann
die deterministisch zugeordnete Regel in die Hardening-Auswahl übernommen werden. Für manuelle
oder nicht abgedeckte Punkte bleibt der KI-Entwurf ein Betreiberplan und wird nicht automatisch
ausgeführt.

## Systemrolle und Hardening-Paket

[#systemrolle-und-hardening-paket](#systemrolle-und-hardening-paket)

Die Systemrolle ändert keine Prüfergebnisse. Sie beschreibt den vorgesehenen Betrieb und sorgt
dafür, dass sensible Änderungen an Netzwerk, SSH, Diensten, Dateisystem, Kryptografie oder Kernel
vor der Paketerstellung ausdrücklich geprüft werden. Zur Auswahl stehen allgemeiner Server,
Mailserver, Webserver, Datenbankserver, KVM-/Virtualisierungshost und Arbeitsstation.

Mehrere Baseline-Einträge werden serverseitig zu einem Plan zusammengeführt. Der Plan:

- übernimmt nur derzeit fehlgeschlagene Regeln aus dem letzten OpenSCAP-Full-Scan,
- entfernt doppelte Regeln,
- blockiert erkannte gegensätzliche Regeln,
- weist manuelle und technisch nicht abgedeckte Punkte getrennt aus,
- verlangt eine Bestätigung für rollenabhängige Betriebsrisiken.

Das exportierte Paket enthält `apply-native-policy.sh`, `verify-native-policy.sh` und
`restore-native-policy.sh`. Apply prüft zuerst die SHA-256-Summen, sichert statisch erkennbare
Konfigurationspfade unter `/var/backups/linux-hardening-agent` und erfasst den Paketbestand.
Restore stellt diese Dateien bestmöglich wieder her. Die drei Skripte sind eigenständige Dateien,
kein Skript mit Modus-Flag: Hochladen führt nichts aus, der Betreiber startet jeden Schritt
getrennt und ausdrücklich mit `sudo ./apply-native-policy.sh`, danach `sudo
./verify-native-policy.sh`, im Problemfall `sudo ./restore-native-policy.sh` gefolgt von
erneuter Prüfung. Paketinstallationen, Bootzustand, Laufzeitparameter und Dienstzustände lassen
sich nicht universell zurückrollen; auf produktiven Systemen bleiben Snapshot/Backup und
getesteter Konsolenzugang deshalb Pflicht.

## Allgemeine Linux-Baseline

[#allgemeine-linux-baseline](#allgemeine-linux-baseline)

Der Full Scan bleibt die technische Messung. Die zusätzliche Baseline ordnet dessen Ergebnisse
distributionsübergreifend nach drei offiziellen Leitfäden ein:

- ANSSI-BP-028 – technische GNU/Linux-Konfiguration
- BSI SYS.1.3 – Linux-/Unix-Server im IT-Grundschutz
- NIST SP 800-123 – allgemeine Serversicherheit

Die GUI bietet die Niveaus Basis, Erhöht und Kritisch sowie einzeln aktivierbare Kategorien. Jeder
Baseline-Punkt wird als bestanden, fehlgeschlagen, nicht anwendbar, manuell, technisch nicht
abgedeckt oder technische Lücke ausgewiesen. Die Zuordnung ist ein transparentes Mapping auf die
Ergebnisse des installierten OpenSCAP-Datenstroms und keine Zertifizierung.

## Voraussetzungen

[#voraussetzungen](#voraussetzungen)

**Agent-Host:** Python 3.11 oder neuer, keine Python-Laufzeitabhängigkeiten (nur `pytest` und
`ruff` für die Entwicklung). Für Debian/Ubuntu als Agent-Host installiert
`scripts/bootstrap-debian.sh` zusätzlich `ca-certificates`, `curl`, `git`, `jq`,
`libvirt-clients`, `openssh-client`, `passwd`, `python3`, `python3-setuptools`, `python3-venv`,
`python3-wheel` und `shellcheck`, optional auch Ollama selbst (`--install-ollama`, `--pull-model`,
`--optimize-ollama`).

**Zielsystem:** ein OpenSCAP-Scanner und das passende SCAP-Inhaltspaket müssen dort vorhanden oder
über die GUI installierbar sein, distributionsabhängig:

| Distribution | Pakete | Befehl |
| --- | --- | --- |
| RHEL, Rocky, AlmaLinux, Oracle Linux | `openscap-scanner`, `scap-security-guide` | `dnf` |
| SLES, SLED, openSUSE Leap/Tumbleweed | `openscap-utils`, `scap-security-guide` | `zypper` |
| Debian | `openscap-scanner`, `ssg-debian` | `apt-get` |
| Ubuntu und weitere Debian-Derivate | `openscap-scanner`, `ssg-debderived` | `apt-get` |

Fehlt eines dieser Pakete, zeigt die GUI den passenden Installationsbefehl an.

## Installation

[#installation](#installation)

Als normaler Benutzer im Projektverzeichnis:

```bash
./scripts/install-local.sh
```

Das Setup erstellt `.venv`, aktualisiert `pip`, `setuptools` und `wheel`, installiert den Agenten,
fragt bei vorhandenem Ollama interaktiv nach `qwen3:8b`, `qwen3:14b`, beiden oder keinem Modell
(nicht-interaktiv steuerbar über `LHA_INSTALL_MODELS=qwen3:8b`, `...,qwen3:14b` oder `none`), und
prüft bei installiertem Vagrant die Eigentümerschaft privater Schlüssel. Verweigert die Ausführung
als root. Danach:

```bash
./scripts/start-gui.sh --model qwen3:8b
```

Wenn bereits eine ältere GUI auf Port 8765 läuft:

```bash
./scripts/restart-gui.sh --model qwen3:8b
```

Die GUI ist unter `http://127.0.0.1:8765` erreichbar. Sie soll nicht als root gestartet werden.
Root-Rechte werden nur auf dem Ziel und nur dort angefordert, wo OpenSCAP oder eine ausdrücklich
bestätigte Massnahme sie benötigt.

Für einen dauerhaften Betrieb als Benutzerdienst:

```bash
./scripts/install-gui-service.sh
```

Richtet `linux-hardening-agent-gui.service` unter `systemd --user` ein. Das Skript verweigert die
Ausführung als root.

Debian 13 enthält im stabilen Paket `ssg-debian` 0.1.76 noch keinen Debian-13-Datenstrom. Die GUI
verwendet niemals ersatzweise den Debian-12-Benchmark. Nach ausdrücklicher Bestätigung lädt der
Agent den vorgebauten offiziellen ComplianceAsCode-0.1.81-Inhalt, prüft die veröffentlichte
SHA-512-Summe und überträgt nur `ssg-debian13-ds.xml` auf das Ziel. Das vollständige Archiv wird
nur auf dem Agent-Rechner zwischengespeichert. Die SHA-512-Prüfung sichert die
Übertragungsintegrität; sie ist keine Signaturprüfung der Quelle, siehe Restrisiken im
Bedrohungsmodell.

## Ollama

[#ollama](#ollama)

Für eine 8-GB-GPU ist `qwen3:8b` die praktische Voreinstellung, `scripts/bootstrap-debian.sh`
verwendet standardmässig `qwen3:14b`. Installierte Modelle können in der GUI ausgewählt werden.
Die Compliance-Bewertung selbst bleibt deterministisch und funktioniert auch ohne Ollama. Passwörter
und private Schlüssel werden nie an Ollama gesendet.

```bash
ollama pull qwen3:8b
```

## Zielarten

[#zielarten](#zielarten)

- lokal
- SSH mit Schlüssel oder Passwort/SSH-Agent gemäss lokaler SSH-Konfiguration
- Vagrant über dessen CLI und Projektverzeichnis
- KVM/libvirt optional

Bei Vagrant verwendet der Agent `vagrant ssh` im erkannten Projektverzeichnis. Private Schlüssel
müssen dafür nicht exportiert oder in die Agent-Konfiguration kopiert werden.

Die KVM-Übersicht liest den Domainzustand sprachunabhängig über `virsh`. Bei laufenden Gästen
versucht sie die IP-Adresse nacheinander über QEMU Guest Agent, libvirt-DHCP-Lease und ARP zu
ermitteln. „Nicht erkannt" bedeutet deshalb: Die VM läuft, aber keine dieser drei Quellen liefert
eine Adresse.

## Unterstützte Prüfquellen

[#unterstützte-prüfquellen](#unterstützte-prüfquellen)

- OpenSCAP/XCCDF für Konfigurations-Hardening
- offizielle OVAL-Paketfeeds für unterstützte Distributionen
- verwaltbare offizielle Herstellerdokumente und Versionszuordnungen

Ein XCCDF-Ergebnis `pass` bedeutet bestanden. Bei OVAL-Vulnerability-Definitionen bedeutet `true`,
dass das System betroffen ist; diese Statusarten werden getrennt dargestellt.

## CLI

[#cli](#cli)

```text
hardening-agent [--version]

hardening-agent target add NAME [--host HOST] [--user USER] [--port PORT]
    [--identity-file PATH] [--local] [--vm-name NAME] [--libvirt-uri URI]
hardening-agent target list

hardening-agent audit TARGET [--output PATH]
hardening-agent doctor [--model MODEL] [--ollama-url URL]
hardening-agent snapshot TARGET
hardening-agent vagrant-access [--operator USER]

hardening-agent gui [--host HOST] [--port PORT] [--output PATH]
    [--libvirt-uri URI] [--no-browser] [--allow-root] [--allow-remote]
    [--model MODEL] [--ollama-url URL]
```

`--model` (Default `qwen3:14b`) und `--ollama-url` (Default `http://127.0.0.1:11434`) gehören zu
`doctor` und `gui`, nicht zum globalen `hardening-agent`-Aufruf selbst.

Beispiele:

```bash
hardening-agent doctor
hardening-agent target add debian-local --local
hardening-agent target list
hardening-agent audit debian-local
hardening-agent gui --no-browser --model qwen3:8b
```

`--allow-root` und `--allow-remote` sind ausdrückliche Troubleshooting-Optionen; siehe
[Sicherheit](#sicherheit) für ihre Risiken.

## Sicherheit

[#sicherheit](#sicherheit)

- GUI bindet standardmässig nur an `127.0.0.1` und verweigert Root-Betrieb, sofern nicht
  ausdrücklich `--allow-root` gesetzt wird.
- Zustandsändernde API-Aufrufe und Downloads benötigen ein zufälliges, pro Prozess erzeugtes
  Token (per `X-LHA-CSRF`-Header, konstante-Zeit-Vergleich), lokale `Host`-Header werden
  validiert, JSON-Anfragen sind auf `Content-Type: application/json` und 64 KiB begrenzt, und die
  GUI sendet restriktive Browser-Sicherheits-Header (`Content-Security-Policy`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).
- `--allow-remote` hebt die Loopback-Bindung auf. Die GUI besitzt weiterhin keine
  Konto-Authentifizierung und kein TLS; dieses Flag sollte nicht in einem nicht
  vertrauenswürdigen Netzwerk verwendet werden.
- Inventar und Scanberichte werden lokal gespeichert.
- Ziele laden keine Richtlinien aus dem Internet; der Agent verwaltet Quellen und Transporte.
  Online-Erkennung von Leitfäden akzeptiert nur HTTPS-Treffer aus einer distributionsspezifischen
  Vendor-Allowlist.
- SSH läuft über den System-OpenSSH-Client mit aktivierter Host-Key-Prüfung.
- Passwörter und private SSH-Schlüssel werden nie an Ollama gesendet; Qwen erhält ausschliesslich
  Quellmetadaten und fehlgeschlagene Baseline-Zuordnungen als Kontext, keine ausführbaren Inhalte.
- Massnahmen benötigen eine ausdrückliche Auswahl und Bestätigung; ein Hochladen aufs Ziel führt
  nichts aus, Apply, Verify und Restore sind getrennte Skripte, die der Betreiber einzeln und
  ausdrücklich mit `sudo` startet.
- Vor produktiver Anwendung sind Snapshot/Backup und Konsolenzugang erforderlich.
- Sicherheitslücken (Command-Injection, Privilege-Escalation, Secret-Disclosure, unsicheres
  Rollback, Remote-Lockout) bitte nicht als öffentliches Issue melden, sondern den Maintainer
  privat kontaktieren, siehe [`SECURITY.md`](SECURITY.md).

Der erste Release ist kein Zertifizierungsprodukt. Generierte Pakete vor dem Produktivbetrieb
prüfen und auf entbehrlichen Systemen testen.

## Entwicklung

[#entwicklung](#entwicklung)

```bash
./.venv/bin/python -m pytest
./.venv/bin/python -m ruff check src tests
node --check src/hardening_agent/web/app.js
```

Beiträge folgen [`CONTRIBUTING.md`](CONTRIBUTING.md): eine Regeländerung pro Branch, mit
autoritativen Quellenangaben, Prüf-, Remediation-, Verify- und Rollback-Logik sowie Tests.
`pytest`, `ruff` und `shellcheck` gegen ein generiertes Paket müssen bestehen. Modellgenerierter
Shell-Text darf nie in ein Paket gelangen. Regeländerungen benötigen ein Security-Review; eine
reine Quell-URL genügt nicht, verlangt werden Dokumenttitel, gültige Version, Kontrollreferenz und
Prüfdatum.

Lizenz: Apache-2.0.
