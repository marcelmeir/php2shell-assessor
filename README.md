# PHP2Shell Assessor

[![Tests](https://github.com/marcelmeir/php2shell-assessor/actions/workflows/tests.yml/badge.svg)](https://github.com/marcelmeir/php2shell-assessor/actions/workflows/tests.yml)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Deutsche Dokumentation](docs/README.de.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

PHP2Shell Assessor is a defensive, non-invasive Python tool for discovering web
services and publicly visible PHP indicators in authorized IPv4 networks. It
helps security teams prioritize manual review for CVE-2026-109618 and
CVE-2026-109619 without attempting exploitation.

The scanner only performs bounded TCP connection checks and small HTTP `GET`
requests. It does **not** exploit vulnerabilities, authenticate, write to remote
systems, fuzz parameters, perform denial-of-service tests, or follow redirects.

## Features

- Memory-efficient IPv4 CIDR, individual address, and exclusion handling
- Asynchronous HTTP/HTTPS discovery with configurable concurrency and rate limits
- Authorized virtual-host testing with HTTP `Host` and TLS SNI
- Domain lists from TXT, LIST, CSV, TSV, XLSX, and XLSM files
- Automatic recognition of common Domain, DNS name, Hostname, FQDN, and IP columns
- Strict IP-scope enforcement for resolved domain names
- Reverse DNS, redirects, server headers, TLS metadata, and certificate fingerprints
- PHP confidence levels with documented evidence for each result
- Common PHP application signatures such as WordPress, Drupal, Joomla, TYPO3,
  Nextcloud, MediaWiki, and Moodle
- Version-baseline assessment with explicit separation between observed,
  suspected, and inventory-verified patch status
- SQLite checkpoints for safe interruption and resume
- CSV reports and a formatted Excel workbook with a dashboard
- Linux, macOS, and Windows launchers
- A dry-run mode that validates the complete scope without starting TCP/HTTP scans

## Requirements

- Python 3.12 or newer
- Linux, macOS, or Windows
- Explicit authorization for every target network

## Quick start

1. Download or clone this repository.
2. Copy `scan_config.example.toml` to `scan_config.toml`.
3. Enter the authorized networks and optional domain list.
4. Set `authorization_confirmed = true` only after the scope is approved.
5. Start the scanner:

Linux or macOS:

```bash
./start_scan.sh
```

Windows:

```bat
start_scan.cmd
```

The launcher creates a local virtual environment and installs the required
packages. Administrative privileges are not required.

## Minimal configuration

```toml
[scope]
authorization_confirmed = true
networks = ["192.0.2.0/24"]
addresses = []
exclude = []
domain_list = "domains.xlsx"
resolve_domains = true

[scan]
ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 9443]
paths = ["/", "/index.php", "/login.php"]
concurrency = 50
connect_timeout = 3
http_timeout = 5
max_rate = 100
retries = 1
dry_run = true

[report]
output = "./results/first-scan"
fresh = false
```

Run once with `dry_run = true`. Review the displayed target count and
`domain_scope_report.csv`, then set it to `false` for the approved scan.

## Domain-list behavior

Domain names never expand the configured network scope. The tool resolves names
through the system resolver, retains only IPv4 mappings inside the configured
targets, and records external, unresolved, invalid, and wildcard names in
`domain_scope_report.csv`.

Set `resolve_domains = false` when DNS names must not be disclosed to the system
resolver. In that mode, the input must provide explicit IP/hostname mappings.

Supported columns include:

- `Domain`, `Domain name`, `DNS`, `DNS name`
- `Host`, `Hostname`, `FQDN`, `Owner name`
- `IP`, `IP address`, `IP addresses`, `IPv4`
- Optional: `Status`, `DNS status`, `State`

## Direct CLI usage

```bash
python php2shell_scanner.py \
  --network 192.0.2.0/24 \
  --domain-list domains.xlsx \
  --exclude exclude.txt \
  --concurrency 50 \
  --max-rate 100 \
  --output ./results/example
```

Use `python php2shell_scanner.py --help` for all options.

## Assessment baselines

| PHP branch | Minimum upstream version |
|---|---:|
| PHP 8.5 | 8.5.12 |
| PHP 8.4 | 8.4.27 |
| PHP 8.3 | 8.3.36 |
| PHP 8.2 | 8.2.35 |

The baselines follow the PHP security releases published on 21 October 2026 in
the [official PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5).

### Important interpretation limits

An HTTP-visible PHP version is not authoritative. Headers can be absent, stale,
proxied, or intentionally misleading. Linux distributions may backport security
fixes without changing the visible upstream version.

`CRITICAL` therefore means that an observed version is below the configured
upstream baseline and requires urgent verification. It is not proof of
exploitability. `PATCH_LEVEL_DETECTED` is also not a verified patch status.
Verification requires trusted inventory data or an authenticated administrative
check. No visible PHP evidence never proves that PHP is absent.

## Reports

The output directory contains:

- `scan_results.xlsx`
- `all_hosts.csv`
- `webservers.csv`
- `php_detected.csv`
- `php_critical.csv`
- `manual_review.csv`
- `domain_scope_report.csv` when a domain list is supplied
- `hostnames_in_scope.txt` when a domain list is supplied
- `scan_checkpoint.sqlite3`
- `scan.log`

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Responsible use

Only scan networks for which you have explicit authorization. Coordinate scan
windows and monitoring expectations with the responsible network operations
team. Start with a small subnet and conservative settings.

## License

Released under the [MIT License](LICENSE).
