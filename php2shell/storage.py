from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import HostResult, ServiceResult


class ResultStore:
    """Durable scan checkpoint and result store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS hosts (ip TEXT PRIMARY KEY, data TEXT NOT NULL)"
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS services (
               ip TEXT NOT NULL, hostname TEXT NOT NULL, port INTEGER NOT NULL,
               data TEXT NOT NULL, PRIMARY KEY (ip, hostname, port))"""
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self.connection.commit()

    def set_metadata(self, key: str, value: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", (key, value)
        )
        self.connection.commit()

    def get_metadata(self, key: str) -> str | None:
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def completed_ips(self) -> set[str]:
        return {row[0] for row in self.connection.execute("SELECT ip FROM hosts")}

    def save_host(self, host: HostResult, services: Iterable[ServiceResult]) -> None:
        with self.connection:
            for service in services:
                self.connection.execute(
                    "INSERT OR REPLACE INTO services(ip, hostname, port, data) VALUES (?, ?, ?, ?)",
                    (
                        service.ip_address,
                        service.hostname,
                        service.port,
                        json.dumps(service.to_dict(), ensure_ascii=False),
                    ),
                )
            self.connection.execute(
                "INSERT OR REPLACE INTO hosts(ip, data) VALUES (?, ?)",
                (host.ip_address, json.dumps(host.to_dict(), ensure_ascii=False)),
            )

    def hosts(self) -> list[dict[str, Any]]:
        return [
            json.loads(row[0])
            for row in self.connection.execute("SELECT data FROM hosts ORDER BY ip")
        ]

    def services(self) -> list[dict[str, Any]]:
        return [
            json.loads(row[0])
            for row in self.connection.execute(
                "SELECT data FROM services ORDER BY ip, hostname, port"
            )
        ]

    def service_stats(self) -> dict[str, int]:
        stats = {"webservers": 0, "php": 0, "critical": 0}
        for (payload,) in self.connection.execute("SELECT data FROM services"):
            row = json.loads(payload)
            stats["webservers"] += 1
            stats["php"] += row.get("php_confidence") != "UNKNOWN"
            stats["critical"] += row.get("security_assessment") == "CRITICAL"
        return stats

    def close(self) -> None:
        self.connection.close()
