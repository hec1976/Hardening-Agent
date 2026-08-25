# Linux Hardening Agent

Lokale Weboberfläche für vollständige Linux-Compliance-Prüfungen mit OpenSCAP/XCCDF,
offiziellen OVAL-Schwachstellenfeeds und einer lokalen Risiko-Priorisierung durch Ollama/Qwen.

Der Agent besitzt keinen eigenen festen Hardening-Regelkatalog. Der Prüfumfang stammt aus dem
zur erkannten Distribution und Hauptversion passenden SCAP-Datenstrom. Der Full Scan erstellt
daraus ein unabhängiges Vollprofil und versucht alle Regeln des Benchmarks auszuwerten.

## Bedrohungsmodell

[#bedrohungsmodell](#bedrohungsmodell)

Der Agent unterscheidet drei Vertrauensbereiche:

- **Agent-Host:** führt die GUI und die Auswertung aus, hält Inventar und Scanberichte lokal.
  Angenommener Angreifer: ein Prozess oder Benutzer ohne Zugriff auf das GUI-Sitzungstoken.
  Nicht abgedeckt: ein bereits kompromittierter Agent-Host selbst, dieser gilt als vertrauenswürdig.
- **Ziel (lokal, SSH, Vagrant, KVM):** wird ausschliesslich read-only gescannt, bis der Betreiber
  ein Massnahmenpaket ausdrücklich erstellt und überträgt. Angenommener Angreifer: ein Ziel, das
  während des Scans manipulierte Antworten liefert. Root-Rechte werden nur dort angefordert, wo
  OpenSCAP oder eine bestätigte Massnahme sie zwingend benötigt.
- **Externe Quellen (SCAP-/OVAL-Feeds, ComplianceAsCode-Archiv):** werden als potenziell
  kompromittierbar behandelt und deshalb per Prüfsumme verifiziert, bevor Inhalte an ein Ziel
  gehen. Siehe Einschränkung zur Authentizität unten.

Ausserhalb des Bedrohungsmodells liegen: ein root-kompromittierter Agent-Host, ein bösartiger
lokaler Mehrbenutzer-Betrieb ohne zusätzliche Betriebssystem-Isolation, und ein Ziel, das schon
vor dem ersten Scan vollständig durch den Angreifer kontrolliert wird.

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
Restore stellt diese Dateien bestmöglich wieder her. Paketinstallationen, Bootzustand,
Laufzeitparameter und Dienstzustände lassen sich nicht universell zurückrollen. Das ist eine
bewusste Risikoakzeptanz und keine technische Lücke, die noch geschlossen werden soll: eine
vollständige Rückrollbarkeit auf Betriebssystemebene würde den Agenten in einen vollwertigen
Konfigurationsmanagement-Systemzustand-Tracker verwandeln, was ausserhalb des Projektumfangs
liegt. Auf produktiven Systemen bleiben Snapshot/Backup und getesteter Konsolenzugang deshalb
Pflicht, aktuell durchgesetzt als Betriebsanweisung und nicht technisch blockierend vor dem Apply.

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

## Installation

[#installation](#installation)

Als normaler Benutzer im Projektverzeichnis:

```
./scripts/install-local.sh
```

Das Setup erstellt `.venv`, aktualisiert `pip`, `setuptools` und `wheel`, installiert den Agenten
und prüft optionale Werkzeuge. Danach:

```
./scripts/start-gui.sh --model qwen3:8b
```

Wenn bereits eine ältere GUI auf Port 8765 läuft:

```
./scripts/restart-gui.sh --model qwen3:8b
```

Die GUI ist unter `http://127.0.0.1:8765` erreichbar. Sie soll nicht als root gestartet werden.
Root-Rechte werden nur auf dem Ziel und nur dort angefordert, wo OpenSCAP oder eine ausdrücklich
bestätigte Massnahme sie benötigt.

Debian 13 enthält im stabilen Paket `ssg-debian` 0.1.76 noch keinen Debian-13-Datenstrom. Die GUI
verwendet niemals ersatzweise den Debian-12-Benchmark. Nach ausdrücklicher Bestätigung lädt der
Agent den vorgebauten offiziellen ComplianceAsCode-0.1.81-Inhalt, prüft die veröffentlichte
SHA-512-Summe und überträgt nur `ssg-debian13-ds.xml` auf das Ziel. Das vollständige Archiv wird
nur auf dem Agent-Rechner zwischengespeichert. Die SHA-512-Prüfung stellt Übertragungsintegrität
sicher, ist aber keine Authentizitätsprüfung: wird die Quelle selbst kompromittiert, könnten Datei
und veröffentlichte Summe gemeinsam ausgetauscht werden. Eine Signaturprüfung des Archivs ist
derzeit nicht implementiert und als bekannte Einschränkung dokumentiert statt stillschweigend
vorausgesetzt.

## Ollama

[#ollama](#ollama)

Für eine 8-GB-GPU ist `qwen3:8b` die praktische Voreinstellung. Installierte Modelle können in
der GUI ausgewählt werden. Die Compliance-Bewertung selbst bleibt deterministisch und funktioniert
auch ohne Ollama.

```
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

```
hardening-agent doctor
hardening-agent target add debian-local --local
hardening-agent target list
hardening-agent audit debian-local
hardening-agent gui --no-browser --model qwen3:8b
```

## Sicherheit

[#sicherheit](#sicherheit)

- GUI bindet standardmässig nur an `127.0.0.1`.
- Zustandsändernde API-Aufrufe benötigen ein sitzungsgebundenes Token.
- Inventar und Scanberichte werden lokal gespeichert.
- Ziele laden keine Richtlinien aus dem Internet; der Agent verwaltet Quellen und Transporte.
- Massnahmen benötigen eine ausdrückliche Auswahl und Bestätigung.
- Vor produktiver Anwendung sind Snapshot/Backup und Konsolenzugang erforderlich.

## Bekannte Einschränkungen und Risikoakzeptanz

[#bekannte-einschränkungen-und-risikoakzeptanz](#bekannte-einschränkungen-und-risikoakzeptanz)

Diese Punkte sind bewusste Designentscheidungen oder aktuelle Grenzen, keine übersehenen Lücken:

- **Prüfsumme statt Signatur:** externe SCAP-/ComplianceAsCode-Inhalte werden per Hash, nicht per
  kryptografischer Signatur verifiziert. Schützt vor Übertragungsfehlern, nicht vor einer
  kompromittierten Quelle.
- **Kein technisch erzwungener Rollback-Schutz:** Snapshot/Backup vor produktivem Apply ist
  Betriebsanweisung, keine vom Agenten blockierte Voraussetzung.
- **Sitzungstoken ohne Mehrbenutzer-Isolation:** die Bindung an `127.0.0.1` verhindert entfernten
  Zugriff, trennt aber auf einem Mehrbenutzer-Host nicht automatisch zwischen lokalen
  Betriebssystem-Benutzern.
- **Agent-Host gilt als vertrauenswürdig:** ein bereits kompromittierter Agent-Host liegt
  ausserhalb des Bedrohungsmodells; es gibt keine Kontrolle, die sich selbst gegen einen
  root-Angreifer auf diesem Host schützt.

## Entwicklung

[#entwicklung](#entwicklung)

```
./.venv/bin/python -m pytest
./.venv/bin/python -m ruff check src tests
node --check src/hardening_agent/web/app.js
```

Lizenz: Apache-2.0.
