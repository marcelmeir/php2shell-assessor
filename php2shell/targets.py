from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Iterator
from pathlib import Path

IPv4Interval = tuple[int, int]


def read_entries(path: str | Path) -> list[str]:
    entries: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8-sig").splitlines():
        value = raw.split("#", 1)[0].strip()
        if value:
            entries.append(value)
    return entries


def _as_interval(value: str, *, usable_hosts: bool) -> IPv4Interval:
    try:
        if "/" not in value:
            addr = ipaddress.ip_address(value)
            if addr.version != 4:
                raise ValueError("IPv6 is not supported in this release")
            number = int(addr)
            return number, number
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 address/network: {value}") from exc
    if net.version != 4:
        raise ValueError(f"IPv6 is not supported in this release: {value}")
    first, last = int(net.network_address), int(net.broadcast_address)
    if usable_hosts and net.prefixlen < 31:
        first, last = first + 1, last - 1
    return first, last


def _merge(intervals: Iterable[IPv4Interval]) -> list[IPv4Interval]:
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(a, b) for a, b in merged]


def _subtract(
    includes: list[IPv4Interval], excludes: list[IPv4Interval]
) -> list[IPv4Interval]:
    result: list[IPv4Interval] = []
    for start, end in includes:
        pieces = [(start, end)]
        for ex_start, ex_end in excludes:
            if ex_end < start:
                continue
            if ex_start > end:
                break
            next_pieces: list[IPv4Interval] = []
            for left, right in pieces:
                if ex_end < left or ex_start > right:
                    next_pieces.append((left, right))
                    continue
                if left < ex_start:
                    next_pieces.append((left, ex_start - 1))
                if ex_end < right:
                    next_pieces.append((ex_end + 1, right))
            pieces = next_pieces
        result.extend(pieces)
    return result


class TargetSet:
    """Compact, restartable IPv4 target iterator backed by integer intervals."""

    def __init__(self, includes: Iterable[str], excludes: Iterable[str] = ()) -> None:
        include_ranges = [_as_interval(item, usable_hosts=True) for item in includes]
        if not include_ranges:
            raise ValueError("At least one IPv4 address or CIDR network is required")
        exclude_ranges = [_as_interval(item, usable_hosts=False) for item in excludes]
        self.intervals = _subtract(_merge(include_ranges), _merge(exclude_ranges))

    @property
    def count(self) -> int:
        return sum(end - start + 1 for start, end in self.intervals)

    def __iter__(self) -> Iterator[str]:
        for start, end in self.intervals:
            for value in range(start, end + 1):
                yield str(ipaddress.IPv4Address(value))

    def contains(self, address: str) -> bool:
        value = int(ipaddress.IPv4Address(address))
        return any(start <= value <= end for start, end in self.intervals)


def load_authorized_hostnames(
    path: str | Path | None, targets: TargetSet
) -> dict[str, list[str]]:
    """Read `IP hostname`/`hostname,IP`; resolve name-only entries but keep in-scope IPs."""
    result: dict[str, set[str]] = {}
    if not path:
        return {}
    for entry in read_entries(path):
        parts = entry.replace(",", " ").split()
        ip = ""
        hostname = ""
        if len(parts) == 2:
            if _is_ipv4(parts[0]):
                ip, hostname = parts[0], parts[1]
            elif _is_ipv4(parts[1]):
                hostname, ip = parts[0], parts[1]
            else:
                raise ValueError(f"Hostname entry needs an IPv4 address: {entry}")
            if not targets.contains(ip):
                raise ValueError(f"Hostname mapping is outside the authorized targets: {entry}")
            result.setdefault(ip, set()).add(hostname.rstrip("."))
        elif len(parts) == 1:
            hostname = parts[0].rstrip(".")
            try:
                resolved = socket.getaddrinfo(hostname, None, socket.AF_INET)
            except socket.gaierror as exc:
                raise ValueError(f"Cannot resolve authorized hostname: {hostname}") from exc
            matched = False
            for item in resolved:
                ip = item[4][0]
                if targets.contains(ip):
                    result.setdefault(ip, set()).add(hostname)
                    matched = True
            if not matched:
                raise ValueError(
                    f"Authorized hostname resolves only outside the target scope: {hostname}"
                )
        else:
            raise ValueError(f"Invalid hostname entry: {entry}")
    return {ip: sorted(names) for ip, names in result.items()}


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False
