# Übergabe- und Betriebsanleitung

## Zweck

PHP2Shell Assessor inventarisiert autorisierte IPv4-Netze auf Webdienste und
öffentlich sichtbare PHP-Indikatoren. Die Anwendung führt keine Exploits, Logins,
Schreibzugriffe, RCE-, DoS- oder Fuzzing-Tests aus.

## Schnellstart für Anwender

1. Das ZIP-Paket in einen eigenen Ordner entpacken.
2. `scan_config.example.toml` als `scan_config.toml` kopieren.
3. Unter `[scope]` die genehmigten IP-Netze eintragen.
4. Optional den Pfad zu einer TXT-, CSV-, TSV- oder Excel-Domainliste eintragen.
5. Nach Prüfung des Scopes `authorization_confirmed = true` setzen.
6. Scan starten:

   - Linux/macOS: `./start_scan.sh`
   - Windows: `start_scan.cmd`

Beim ersten Start wird eine lokale Python-Umgebung im entpackten Ordner erstellt.
Es sind keine administrativen Rechte erforderlich. Der Rechner benötigt beim
ersten Start Zugriff auf PyPI, sofern die Abhängigkeiten nicht intern gespiegelt
werden.

## Minimale Konfiguration

```toml
[scope]
authorization_confirmed = true
networks = ["192.0.2.0/24"]
addresses = []
networks_file = ""
exclude = []
exclude_file = ""
domain_list = "domains.xlsx"
resolve_domains = true
hostnames_file = ""

[scan]
ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 9443]
paths = ["/", "/index.php", "/login.php"]
concurrency = 50
connect_timeout = 3
http_timeout = 5
max_rate = 100
retries = 1
verbose = false
dry_run = false

[report]
output = "./results/mein-scan"
fresh = false

[inventory]
file = ""
```

Relative Pfade beziehen sich auf den Ordner der TOML-Datei. Für jeden fachlich
anderen Scan sollte ein eigener Ausgabeordner verwendet werden. Wird derselbe
Scan nach einem Abbruch erneut gestartet, setzt die Anwendung ihn anhand des
Checkpoints fort.

## Unterstützte Domainlisten

### TXT oder LIST

Eine Zeile pro Name. Eine vorhandene IP kann vor oder hinter dem Namen stehen:

```text
www.example.edu
192.0.2.10 portal.example.edu
```

### CSV oder TSV

Die Anwendung erkennt unter anderem folgende Spaltennamen:

- Domain, Domain name, DNS, DNS name
- Host, Hostname, FQDN, Owner name
- IP, IP address, IP addresses, IPv4
- optional Status, DNS status, State

### XLSX oder XLSM

Die Anwendung sucht in jedem Tabellenblatt innerhalb der ersten 50 Zeilen nach
einer der oben genannten Domainspalten. Titel- und Leerzeilen vor der Tabelle
sind zulässig.

Namen werden über den systemseitig konfigurierten DNS-Resolver aufgelöst. Nur
IPv4-Adressen innerhalb des konfigurierten Scopes werden geprüft. Externe
Auflösungen, Wildcards, ungültige und nicht auflösbare Namen werden in
`domain_scope_report.csv` dokumentiert. Mit `resolve_domains = false` werden nur
IP-Adressen verwendet, die bereits in der Liste stehen.

## Ergebnisse

Der konfigurierte Ausgabeordner enthält:

- `scan_results.xlsx`: formatierter Gesamtbericht
- `all_hosts.csv`: alle abgeschlossenen Zieladressen
- `webservers.csv`: erkannte HTTP-/HTTPS-Dienste
- `php_detected.csv`: bestätigte und vermutete PHP-Nutzung
- `php_critical.csv`: sichtbare Versionsstände unter der Baseline
- `manual_review.csv`: nicht eindeutig bewertbare Systeme
- `domain_scope_report.csv`: Verarbeitung der Domainliste
- `hostnames_in_scope.txt`: tatsächlich verwendete IP/Hostname-Zuordnungen
- `scan_checkpoint.sqlite3`: Wiederaufnahmezustand
- `scan.log`: Laufzeit- und Fehlerprotokoll

## Betriebshinweise

- Zunächst mit einem kleinen Teilnetz und niedriger Rate testen.
- Vor der ersten Freigabe `dry_run = true` setzen. Der Trockenlauf validiert und
  zeigt den vollständigen Scope, ohne TCP- oder HTTP-Verbindungen zu starten.
  Danach für den genehmigten Produktivlauf auf `false` setzen.
- Produktive Scanfenster und Monitoring-Alarme mit dem Netzbetrieb abstimmen.
- Für einen normalen Hochschulbetrieb die Standardwerte `concurrency = 50` und
  `max_rate = 100` nicht ohne Abstimmung erhöhen.
- `fresh = true` verwirft den Checkpoint im Ausgabeordner bewusst. Danach wieder
  auf `false` setzen.
- Der Prozess kann mit `Ctrl+C` beendet werden. Bereits vollständig bearbeitete
  Hosts bleiben gespeichert.
- HTTP-Weiterleitungen werden aufgezeichnet, aber nicht verfolgt.
- Eine Domain, die ausschließlich auf fremde Netze zeigt, wird nicht geprüft.

## Abnahme vor Weitergabe

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
python php2shell_scanner.py --help
```

Die Anwendung benötigt Python 3.12 oder neuer.
