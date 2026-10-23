from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(slots=True)
class InventoryRecord:
    installed_php_version: str = ""
    verified_patch_status: str = "NOT_VERIFIED"
    source: str = ""


class InventoryProvider(Protocol):
    """Extension point for authenticated CMDB/EDR/package inventory adapters."""

    def lookup(self, ip_address: str, hostname: str) -> InventoryRecord | None: ...


class CsvInventoryProvider:
    """Optional trusted import with ip/hostname, version, patch status and source."""

    def __init__(self, path: str | Path) -> None:
        self._by_ip: dict[str, InventoryRecord] = {}
        self._by_host: dict[str, InventoryRecord] = {}
        with Path(path).open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                record = InventoryRecord(
                    installed_php_version=(row.get("installed_php_version") or "").strip(),
                    verified_patch_status=(row.get("verified_patch_status") or "NOT_VERIFIED").strip(),
                    source=(row.get("source") or f"CSV inventory: {path}").strip(),
                )
                if (ip := (row.get("ip_address") or "").strip()):
                    self._by_ip[ip] = record
                if (host := (row.get("hostname") or "").strip().lower()):
                    self._by_host[host] = record

    def lookup(self, ip_address: str, hostname: str) -> InventoryRecord | None:
        return self._by_host.get(hostname.lower()) or self._by_ip.get(ip_address)
