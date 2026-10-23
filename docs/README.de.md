# PHP2Shell Network Discovery & Vulnerability Assessment

Eine defensive Python-Anwendung zur autorisierten, nichtinvasiven Erkennung von
Webdiensten und öffentlich sichtbaren PHP-Indikatoren in definierten IPv4-Netzen.
Sie bewertet die von PHP veröffentlichten Patchstände für CVE-2026-109618 und
CVE-2026-109619, führt jedoch **keine
Exploits, RCE-Tests, Logins, Schreibzugriffe oder Brute-Force-Scans** aus.

## Sicherheitsmodell

- Es werden ausschließlich angegebene IPv4-Ziele und Ports angesprochen.
- HTTP nutzt nur kleine `GET`-Anfragen auf eine feste Pfadliste; Antworten werden
  nach 256 KiB abgeschnitten.
- Weiterleitungen werden erfasst, aber nicht verfolgt. Damit erweitern DNS oder
  Redirects den autorisierten Scanbereich nicht.
- Zusätzliche Hostnamen stammen nur aus der bereitgestellten Datei. Der Scanner
  verbindet diese per festem Resolver mit der zugeordneten Ziel-IP und verwendet
  den Namen für HTTP `Host` und TLS-SNI.
- Parallelität, Start-Rate, Timeouts und Wiederholungen sind begrenzt.
- Ein SQLite-Checkpoint macht abgeschlossene Hosts nach einem Abbruch wiederaufnehmbar.

Die Nutzung ist ausschließlich in Netzen zulässig, für die eine ausdrückliche
Prüfberechtigung vorliegt.

## Voraussetzungen und Installation

- Python 3.12 oder neuer
- Linux, macOS oder Windows

```bash
python3 -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

Alternativ installiert `python -m pip install .` den Befehl
`php2shell-scanner` und den Konfigurationsstarter `php2shell-scan-config`.

## Einfacher Betrieb mit einer Konfigurationsdatei

Für die Weitergabe an andere Teams ist keine lange Kommandozeile erforderlich:

1. `scan_config.example.toml` nach `scan_config.toml` kopieren.
2. Unter `[scope]` den genehmigten Adressbereich und optional eine Domainliste
   eintragen.
3. Nach der Scope-Prüfung `authorization_confirmed = true` setzen.
4. Unter Linux/macOS `./start_scan.sh`, unter Windows `start_scan.cmd` starten.

Beispiel:

```toml
[scope]
authorization_confirmed = true
networks = ["192.0.2.0/24"]
domain_list = "domains.xlsx"
resolve_domains = true
```

Alle weiteren Werte besitzen konservative Vorgaben. Die ausführliche Anleitung
für Betrieb und Übergabe steht in `HANDOVER.md`.

Für die Scope-Abnahme kann unter `[scan]` zunächst `dry_run = true` gesetzt
werden. Dabei werden Konfiguration und Domainliste geprüft, aber keine
TCP-/HTTP-Verbindungen gestartet.

## Erster Scan

1. Autorisierte Netze in `networks.txt` eintragen, je Zeile eine IP oder ein CIDR.
2. Nicht zu prüfende Systeme optional in `exclude.txt` eintragen.
3. Zunächst mit niedriger Last und einem kleinen Netz starten:

```bash
python php2shell_scanner.py \
  --network 192.0.2.0/28 \
  --exclude examples/exclude.txt \
  --ports 80,443,8080,8443 \
  --concurrency 20 \
  --max-rate 40 \
  --timeout 3 \
  --output ./results
```

Die vollständige Beispielkonfiguration liegt unter
`examples/scan-command.txt`. Vor dem Start zeigt die CLI Zielanzahl, Ports,
Parallelität, Rate, Timeouts, virtuelle Hosts und Ausgabeordner an.

Mehrere Netze und einzelne IPs können kombiniert werden:

```bash
python php2shell_scanner.py \
  --networks examples/networks.txt \
  --network 203.0.113.0/28 \
  --ip 203.0.113.100 \
  --exclude examples/exclude.txt \
  --exclude-target 203.0.113.7 \
  --output ./results
```

Mit `Ctrl+C` wird abgebrochen. Derselbe Befehl setzt den Scan anhand von
`scan_checkpoint.sqlite3` fort. Eine andere Ziel-/Port-/Pfadkonfiguration im
gleichen Ausgabeordner wird aus Sicherheitsgründen abgelehnt. `--fresh` startet
bewusst neu und ersetzt den Checkpoint.

## Autorisierte Hostnamen und virtuelle Hosts

Mit `--domain-list domains.xlsx` verarbeitet die Anwendung generische TXT-,
LIST-, CSV-, TSV-, XLSX- und XLSM-Dateien. Sie erkennt verbreitete Spaltennamen
wie `Domain`, `DNS name`, `Hostname`, `FQDN`, `IP` und `IP address` automatisch.
DNS-Namen werden nur mit IPv4-Adressen innerhalb des konfigurierten Scopes
verwendet. Die vollständige Entscheidung je Name wird in
`domain_scope_report.csv` protokolliert. `--no-domain-resolution` verhindert
DNS-Abfragen und verwendet ausschließlich mitgelieferte IP-Adressen.

Für bereits vorbereitete Zuordnungen unterstützt
`--hostnames examples/hostnames.txt` weiterhin:

```text
192.0.2.5 www.example.edu
portal.example.edu,192.0.2.5
```

Ein Name ohne IP darf ebenfalls angegeben werden. Er wird einmal per DNS
aufgelöst, aber nur Zieladressen innerhalb der bereits definierten Netze werden
verwendet. Ein explizites Mapping außerhalb des Zielbereichs ist ein Fehler.
Mehrere Namen auf derselben IP werden als getrennte Webdienste dokumentiert.

## Erkennung und Bewertung

Signale sind nachvollziehbar im Feld `detection_evidence` dokumentiert:

- `CONFIRMED`: direkter PHP-Nachweis, z. B. `X-Powered-By: PHP/8.3.36`
- `HIGH`: mehrere starke/zusätzliche öffentliche PHP-Indikatoren
- `MEDIUM`: ein starker oder mehrere schwache indirekte Hinweise
- `LOW`: schwacher Hinweis
- `UNKNOWN`: keine belastbaren Hinweise

Ein Cookie wie `PHPSESSID` allein ist kein bestätigter Nachweis. Erkannte
Anwendungssignaturen umfassen WordPress, Drupal, Joomla, TYPO3, Nextcloud,
MediaWiki und Moodle.

Konfigurierte Upstream-Mindeststände:

| Zweig | Mindeststand |
|---|---:|
| PHP 8.5 | 8.5.12 |
| PHP 8.4 | 8.4.27 |
| PHP 8.3 | 8.3.36 |
| PHP 8.2 | 8.2.35 |

Die Statuswerte lauten `CRITICAL`, `PATCH_LEVEL_DETECTED`,
`PHP_VERSION_UNKNOWN`, `PHP_SUSPECTED`, `WEB_SERVER_FOUND`, `NO_WEB_SERVICE`
und `SCAN_ERROR`.

### Wichtige Grenzen der nichtauthentifizierten Erkennung

Ein Webserver kann PHP einsetzen, ohne es in Headern, Cookies oder HTML sichtbar
zu machen. Reverse Proxies und Load Balancer können Signale entfernen, ergänzen
oder einem Backend falsch zuordnen. Header können absichtlich gefälscht sein.
Ein sichtbarer Versionsstring beschreibt nicht zwingend das tatsächlich geladene
Paket. Besonders Linux-Distributionen können Sicherheitskorrekturen
zurückportieren, ohne die Upstream-Versionsnummer auf den hier genannten Stand zu
heben.

Darum bedeutet `CRITICAL` in diesem Bericht: **anhand der beobachteten
Upstream-Versionsnummer potenziell betroffen und dringend zu verifizieren**. Es
ist kein Exploit-Nachweis. `PATCH_LEVEL_DETECTED` bedeutet nur, dass der sichtbare
String mindestens dem Baseline-Wert entspricht. Der Scanner setzt
`verified_patch_status` ohne vertrauenswürdige Inventardaten stets auf
`NOT_VERIFIED`. Kein PHP-Signal bedeutet niemals, dass PHP nicht installiert ist.

## Optionale authentifizierte Inventarschnittstelle

`InventoryProvider` in `php2shell/inventory.py` ist die Erweiterungsschnittstelle
für CMDB, EDR, Intune, Paketverwaltung oder eine zukünftige administrative
SSH-Prüfung. Bereits nutzbar ist ein vertrauenswürdiger CSV-Import:

```bash
python php2shell_scanner.py \
  --network 192.0.2.0/28 \
  --inventory examples/inventory.csv \
  --output ./results-with-inventory
```

Spalten: `ip_address`, `hostname`, `installed_php_version`,
`verified_patch_status`, `source`. Eine Inventarversion ersetzt den unzuverlässigen
HTTP-Versionsstring und wird ausdrücklich als authentifizierte Quelle markiert.

## Ergebnisse

Im Ausgabeordner entstehen:

- `all_hosts.csv`
- `webservers.csv`
- `php_detected.csv`
- `php_critical.csv`
- `manual_review.csv`
- `scan_results.xlsx`
- `scan_checkpoint.sqlite3`
- `scan.log`
- `domain_scope_report.csv` und `hostnames_in_scope.txt`, wenn eine Domainliste
  verwendet wird

Die Excel-Datei enthält Dashboard, Kritische Systeme, PHP erkannt, Manuelle
Prüfung, Alle Webserver, Alle Hosts und Scanfehler. Filter, fixierte Kopfzeilen,
angepasste Spaltenbreiten und Statusfarben sind vorkonfiguriert.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

Die Tests decken Patchgrenzen, PHP-Signale, Zielausschlüsse und die CSV-/Excel-
Exporte ab.

## CLI-Referenz

```bash
python php2shell_scanner.py --help
```

Wichtige Optionen sind `--network`, `--networks`, `--ip`, `--exclude`,
`--exclude-target`, `--domain-list`, `--no-domain-resolution`, `--hostnames`,
`--ports`, `--concurrency`, `--timeout`, `--http-timeout`, `--max-rate`,
`--retries`, `--paths`, `--inventory`, `--output`, `--fresh` und `--verbose`.
Zusätzlich validiert `--dry-run` den vollständigen Scope ohne aktiven Scan.
