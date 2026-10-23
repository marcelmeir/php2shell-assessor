from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

from .domain_inputs import DomainPreparation, merge_hostname_maps, prepare_domain_list
from .exporters import export_results
from .inventory import CsvInventoryProvider
from .scanner import NetworkScanner, ScanConfig
from .storage import ResultStore
from .targets import TargetSet, load_authorized_hostnames, read_entries

DEFAULT_PORTS = "80,443,8080,8443,8000,8008,8888,9443"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized, non-invasive PHP web-service discovery and assessment."
    )
    parser.add_argument("--network", action="append", default=[], help="IPv4 CIDR (repeatable)")
    parser.add_argument("--ip", action="append", default=[], help="Single IPv4 address (repeatable)")
    parser.add_argument(
        "--networks", "--networks-file", dest="networks_file", help="Text file with CIDRs/IPs"
    )
    parser.add_argument("--exclude", dest="exclude_file", help="Text file with excluded CIDRs/IPs")
    parser.add_argument(
        "--exclude-target", action="append", default=[], help="Excluded CIDR/IP (repeatable)"
    )
    parser.add_argument("--hostnames", help="Authorized hostname mapping file")
    parser.add_argument(
        "--domain-list", help="Domain list in TXT, CSV, TSV, XLSX or XLSM format"
    )
    parser.add_argument(
        "--no-domain-resolution",
        action="store_true",
        help="Use supplied IP columns only; do not resolve DNS names",
    )
    parser.add_argument("--ports", default=DEFAULT_PORTS, help="Comma-separated TCP ports")
    parser.add_argument("--concurrency", type=int, default=50, help="Maximum concurrent hosts")
    parser.add_argument("--timeout", type=float, default=3.0, help="TCP connect timeout in seconds")
    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP request timeout")
    parser.add_argument("--max-rate", type=float, default=100.0, help="Network operations per second")
    parser.add_argument("--retries", type=int, default=1, help="HTTP retries with backoff")
    parser.add_argument(
        "--paths", default="/,/index.php,/login.php", help="Small comma-separated path allowlist"
    )
    parser.add_argument("--output", default="./results", help="Output directory")
    parser.add_argument("--inventory", help="Optional trusted inventory CSV")
    parser.add_argument("--fresh", action="store_true", help="Start over instead of resuming checkpoint")
    parser.add_argument(
        "--dry-run", action="store_true", help="Validate and show the complete scope without scanning"
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(output / "scan.log", encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.getLogger().addHandler(file_handler)
    domain_preparation: DomainPreparation | None = None
    try:
        inputs = list(args.network) + list(args.ip)
        if args.networks_file:
            inputs.extend(read_entries(args.networks_file))
        exclusions = list(args.exclude_target)
        if args.exclude_file:
            exclusions.extend(read_entries(args.exclude_file))
        targets = TargetSet(inputs, exclusions)
        if targets.count == 0:
            raise ValueError("All targets were excluded")
        ports = _parse_ports(args.ports)
        paths = tuple(_parse_paths(args.paths))
        if not 1 <= args.concurrency <= 1000:
            raise ValueError("--concurrency must be between 1 and 1000")
        if args.timeout <= 0 or args.http_timeout <= 0 or args.max_rate <= 0:
            raise ValueError("Timeouts and maximum rate must be greater than zero")
        if not 0 <= args.retries <= 10:
            raise ValueError("--retries must be between 0 and 10")
        explicit_hostnames = load_authorized_hostnames(args.hostnames, targets)
        domain_hostnames: dict[str, list[str]] = {}
        if args.domain_list:
            domain_preparation = prepare_domain_list(
                args.domain_list,
                targets,
                output,
                resolve_dns=not args.no_domain_resolution,
            )
            domain_hostnames = domain_preparation.hostnames
        hostnames = merge_hostname_maps(explicit_hostnames, domain_hostnames)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]Configuration error:[/] {exc}")
        return 2

    checkpoint = output / "scan_checkpoint.sqlite3"
    if args.dry_run:
        resumed = 0
        if checkpoint.exists():
            dry_store = ResultStore(checkpoint)
            resumed = len(dry_store.completed_ips())
            dry_store.close()
        _show_plan(
            console,
            targets.count,
            ports,
            args,
            resumed,
            hostnames,
            domain_preparation,
        )
        console.print("[bold green]Dry run complete. No TCP or HTTP scan was started.[/]")
        return 0
    if args.fresh and checkpoint.exists():
        checkpoint.unlink()
    store = ResultStore(checkpoint)
    signature = _scan_signature(targets, ports, paths, hostnames)
    old_signature = store.get_metadata("scan_signature")
    if old_signature and old_signature != signature:
        store.close()
        console.print(
            "[bold red]The existing checkpoint belongs to a different target/port configuration.[/] "
            "Choose another output folder or use --fresh."
        )
        return 2
    store.set_metadata("scan_signature", signature)

    _show_plan(
        console,
        targets.count,
        ports,
        args,
        len(store.completed_ips()),
        hostnames,
        domain_preparation,
    )
    logging.info(
        "Starting/resuming authorized scan: targets=%s ports=%s output=%s",
        targets.count,
        ports,
        output,
    )
    config = ScanConfig(
        ports=ports,
        concurrency=args.concurrency,
        connect_timeout=args.timeout,
        http_timeout=args.http_timeout,
        scan_rate=args.max_rate,
        retries=args.retries,
        paths=paths,
    )
    inventory = CsvInventoryProvider(args.inventory) if args.inventory else None
    interrupted = False
    try:
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            TextColumn("• web {task.fields[web]} • PHP {task.fields[php]} • kritisch {task.fields[critical]}"),
            console=console,
        ) as progress:
            completed = len(store.completed_ips())
            task_id = progress.add_task(
                "Scanning", total=targets.count, completed=completed, web=0, php=0, critical=0
            )

            def update(stats: dict[str, int]) -> None:
                progress.update(
                    task_id,
                    completed=min(stats["hosts"], targets.count),
                    web=stats["webservers"],
                    php=stats["php"],
                    critical=stats["critical"],
                )

            scanner = NetworkScanner(
                config, targets, store, hostnames, inventory, progress_callback=update
            )
            asyncio.run(scanner.run())
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[yellow]Scan interrupted; completed hosts remain checkpointed.[/]")
    except Exception:
        logging.exception("Scan failed")
        interrupted = True

    files = export_results(store, output)
    hosts = store.hosts()
    services = store.services()
    store.close()
    critical_count = sum(row["security_assessment"] == "CRITICAL" for row in services)
    php_count = sum(row["php_confidence"] != "UNKNOWN" for row in services)
    summary = Table(title="Scan summary")
    summary.add_column("Metric")
    summary.add_column("Count", justify="right")
    summary.add_row("Hosts completed", str(len(hosts)))
    summary.add_row("Web services", str(len(services)))
    summary.add_row("PHP detected/suspected", str(php_count))
    summary.add_row("Potentially critical", str(critical_count), style="red" if critical_count else None)
    console.print(summary)
    console.print(f"Results: [bold]{output}[/]")
    console.print(f"Excel report: [bold]{files['excel']}[/]")
    logging.info(
        "Scan finished: hosts=%s services=%s php=%s critical=%s interrupted=%s",
        len(hosts),
        len(services),
        php_count,
        critical_count,
        interrupted,
    )
    return 130 if interrupted else 0


def _parse_ports(value: str) -> list[int]:
    try:
        ports = sorted({int(item.strip()) for item in value.split(",") if item.strip()})
    except ValueError as exc:
        raise ValueError("Ports must be comma-separated integers") from exc
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535")
    return ports


def _parse_paths(value: str) -> list[str]:
    paths = []
    for item in value.split(","):
        path = item.strip()
        if not path:
            continue
        if not path.startswith("/") or "://" in path or "?" in path or "#" in path:
            raise ValueError("Paths must be simple absolute paths without query strings")
        paths.append(path)
    if not paths or len(paths) > 10:
        raise ValueError("Provide between 1 and 10 HTTP paths")
    return paths


def _scan_signature(
    targets: TargetSet, ports: list[int], paths: tuple[str, ...], hostnames: dict[str, list[str]]
) -> str:
    data = {
        "intervals": targets.intervals,
        "ports": ports,
        "paths": paths,
        "hostnames": hostnames,
    }
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _show_plan(
    console: Console,
    target_count: int,
    ports: list[int],
    args: argparse.Namespace,
    resumed: int,
    hostnames: dict[str, list[str]],
    domain_preparation: DomainPreparation | None,
) -> None:
    table = Table(title="Planned authorized scan")
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("IPv4 targets", f"{target_count:,}")
    table.add_row("Ports", ", ".join(map(str, ports)))
    table.add_row("Maximum concurrency", str(args.concurrency))
    table.add_row("Maximum operation rate", f"{args.max_rate:g}/s")
    table.add_row("TCP / HTTP timeout", f"{args.timeout:g}s / {args.http_timeout:g}s")
    table.add_row("Authorized virtual hosts", str(sum(map(len, hostnames.values()))))
    if domain_preparation:
        table.add_row("Domain names in scope", str(domain_preparation.in_scope_names))
        table.add_row("Domains outside scope", str(domain_preparation.outside_scope_names))
        table.add_row("Domains unresolved", str(domain_preparation.unresolved_names))
        table.add_row("Wildcards skipped", str(domain_preparation.skipped_wildcards))
    table.add_row("Already checkpointed", str(resumed))
    table.add_row("Output", str(Path(args.output).expanduser().resolve()))
    console.print(table)
    console.print(
        "[dim]Only TCP connect and bounded GET requests are used. Redirects are recorded, not followed. "
        "Run only against networks you are authorized to assess.[/]"
    )
