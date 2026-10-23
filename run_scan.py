#!/usr/bin/env python3
"""Simple TOML configuration launcher for PHP2Shell Assessor."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import Any

from php2shell.cli import main as scanner_main


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start a scan from a TOML configuration file")
    parser.add_argument("config", nargs="?", default="scan_config.toml")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).expanduser().resolve()
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        scanner_args = config_to_args(config, config_path.parent)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    return scanner_main(scanner_args)


def config_to_args(config: dict[str, Any], base_dir: Path) -> list[str]:
    _validate_keys(config, {"scope", "scan", "report", "inventory"}, "top level")
    scope = _table(config, "scope")
    scan = _table(config, "scan")
    report = _table(config, "report")
    inventory = _table(config, "inventory")
    _validate_keys(
        scope,
        {
            "authorization_confirmed",
            "networks",
            "addresses",
            "exclude",
            "networks_file",
            "exclude_file",
            "domain_list",
            "resolve_domains",
            "hostnames_file",
        },
        "[scope]",
    )
    _validate_keys(
        scan,
        {
            "ports",
            "paths",
            "concurrency",
            "connect_timeout",
            "http_timeout",
            "max_rate",
            "retries",
            "verbose",
            "dry_run",
        },
        "[scan]",
    )
    _validate_keys(report, {"output", "fresh"}, "[report]")
    _validate_keys(inventory, {"file"}, "[inventory]")
    result: list[str] = []
    if scope.get("authorization_confirmed") is not True:
        raise ValueError(
            "scope.authorization_confirmed must be true after the scan scope has been authorized"
        )
    for network in _strings(scope.get("networks", []), "scope.networks"):
        result += ["--network", network]
    for address in _strings(scope.get("addresses", []), "scope.addresses"):
        result += ["--ip", address]
    for excluded in _strings(scope.get("exclude", []), "scope.exclude"):
        result += ["--exclude-target", excluded]
    _optional_path(result, "--networks", scope.get("networks_file"), base_dir)
    _optional_path(result, "--exclude", scope.get("exclude_file"), base_dir)
    _optional_path(result, "--domain-list", scope.get("domain_list"), base_dir)
    _optional_path(result, "--hostnames", scope.get("hostnames_file"), base_dir)
    if scope.get("resolve_domains") is False:
        result.append("--no-domain-resolution")

    ports = _strings(
        scan.get("ports", [80, 443, 8080, 8443, 8000, 8008, 8888, 9443]),
        "scan.ports",
    )
    paths = scan.get("paths", ["/", "/index.php", "/login.php"])
    result += ["--ports", ",".join(str(value) for value in ports)]
    result += ["--paths", ",".join(_strings(paths, "scan.paths"))]
    for key, flag, default in (
        ("concurrency", "--concurrency", 50),
        ("connect_timeout", "--timeout", 3),
        ("http_timeout", "--http-timeout", 5),
        ("max_rate", "--max-rate", 100),
        ("retries", "--retries", 1),
    ):
        result += [flag, str(scan.get(key, default))]

    output_value = report.get("output", "./results")
    result += ["--output", str(_path(output_value, base_dir))]
    if report.get("fresh") is True:
        result.append("--fresh")
    if scan.get("verbose") is True:
        result.append("--verbose")
    if scan.get("dry_run") is True:
        result.append("--dry-run")
    _optional_path(result, "--inventory", inventory.get("file"), base_dir)
    return result


def _table(config: dict[str, Any], name: str) -> dict[str, Any]:
    value = config.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"[{name}] must be a TOML table")
    return value


def _validate_keys(values: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(f"Unknown setting(s) in {location}: {', '.join(unknown)}")


def _strings(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, (str, int)) for item in value):
        raise ValueError(f"{name} must be a list")
    return [str(item) for item in value]


def _path(value: Any, base_dir: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("File paths must be non-empty strings")
    path = Path(value).expanduser()
    return path if path.is_absolute() else (base_dir / path).resolve()


def _optional_path(result: list[str], flag: str, value: Any, base_dir: Path) -> None:
    if value in (None, ""):
        return
    result += [flag, str(_path(value, base_dir))]


if __name__ == "__main__":
    raise SystemExit(main())
