from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from .assessment import assess_php
from .detection import Detection, detect_php, merge_detections
from .inventory import InventoryProvider
from .models import HostResult, ServiceResult
from .rate_limit import RateLimiter
from .storage import ResultStore
from .targets import TargetSet

LOG = logging.getLogger(__name__)
TLS_PORTS = {443, 8443, 9443}
MAX_BODY_BYTES = 262_144


class FixedResolver(AbstractResolver):
    def __init__(self, hostname: str, ip_address: str) -> None:
        self.hostname = hostname.lower()
        self.ip_address = ip_address

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        if host.lower() != self.hostname:
            raise OSError(f"Refusing to resolve unapproved hostname: {host}")
        return [{
            "hostname": host,
            "host": self.ip_address,
            "port": port,
            "family": socket.AF_INET,
            "proto": socket.IPPROTO_TCP,
            "flags": 0,
        }]

    async def close(self) -> None:
        return None


@dataclass(slots=True)
class ScanConfig:
    ports: list[int]
    concurrency: int = 50
    connect_timeout: float = 3.0
    http_timeout: float = 5.0
    scan_rate: float = 100.0
    retries: int = 1
    paths: tuple[str, ...] = ("/", "/index.php", "/login.php")
    user_agent: str = "PHP2Shell-Authorized-Security-Scanner/1.0"


class NetworkScanner:
    def __init__(
        self,
        config: ScanConfig,
        targets: TargetSet,
        store: ResultStore,
        hostnames: dict[str, list[str]] | None = None,
        inventory: InventoryProvider | None = None,
        progress_callback: Any = None,
    ) -> None:
        self.config = config
        self.targets = targets
        self.store = store
        self.hostnames = hostnames or {}
        self.inventory = inventory
        self.progress_callback = progress_callback
        self.rate_limiter = RateLimiter(config.scan_rate)
        self.stop_event = asyncio.Event()
        self.stats = {"hosts": 0, "webservers": 0, "php": 0, "critical": 0}

    async def run(self) -> dict[str, int]:
        completed = self.store.completed_ips()
        self.stats["hosts"] = len(completed)
        self.stats.update(self.store.service_stats())
        if self.progress_callback:
            self.progress_callback(self.stats)
        queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=self.config.concurrency * 2)

        async def producer() -> None:
            for ip_address in self.targets:
                if self.stop_event.is_set():
                    break
                if ip_address not in completed:
                    await queue.put(ip_address)
            for _ in range(self.config.concurrency):
                await queue.put(None)

        async def worker() -> None:
            while True:
                ip_address = await queue.get()
                try:
                    if ip_address is None:
                        return
                    host, services = await self.scan_host(ip_address)
                    self.store.save_host(host, services)
                    self.stats["hosts"] += 1
                    self.stats["webservers"] += len(services)
                    self.stats["php"] += sum(
                        service.php_confidence != "UNKNOWN" for service in services
                    )
                    self.stats["critical"] += sum(
                        service.security_assessment == "CRITICAL" for service in services
                    )
                    if self.progress_callback:
                        self.progress_callback(self.stats)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    LOG.exception("Unhandled error while scanning %s", ip_address)
                    host = HostResult(
                        ip_address=ip_address or "", status="SCAN_ERROR", error=str(exc)
                    )
                    self.store.save_host(host, [])
                    self.stats["hosts"] += 1
                finally:
                    queue.task_done()

        producer_task = asyncio.create_task(producer())
        workers = [asyncio.create_task(worker()) for _ in range(self.config.concurrency)]
        try:
            await producer_task
            await queue.join()
        except asyncio.CancelledError:
            self.stop_event.set()
            raise
        finally:
            for task in workers:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        return self.stats

    async def scan_host(self, ip_address: str) -> tuple[HostResult, list[ServiceResult]]:
        reverse_dns = await self._reverse_dns(ip_address)
        services: list[ServiceResult] = []
        for port in self.config.ports:
            is_open, _error = await self._tcp_open(ip_address, port)
            if not is_open:
                continue
            names: list[str | None] = [None]
            names.extend(self.hostnames.get(ip_address, []))
            for hostname in names:
                service = await self._scan_web_service(
                    ip_address, port, hostname, reverse_dns
                )
                if service:
                    services.append(service)
        host = HostResult(
            ip_address=ip_address,
            reverse_dns=reverse_dns,
            reachable=bool(services),
            web_service_count=len(services),
            status="WEB_SERVER_FOUND" if services else "NO_WEB_SERVICE",
            error="",
        )
        return host, services

    async def _reverse_dns(self, ip_address: str) -> str:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip_address),
                timeout=self.config.connect_timeout,
            )
            return result[0].rstrip(".")
        except (OSError, asyncio.TimeoutError):
            return ""

    async def _tcp_open(self, ip_address: str, port: int) -> tuple[bool, str]:
        writer: asyncio.StreamWriter | None = None
        try:
            await self.rate_limiter.wait()
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip_address, port),
                timeout=self.config.connect_timeout,
            )
            return True, ""
        except (OSError, asyncio.TimeoutError) as exc:
            return False, str(exc)
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    async def _scan_web_service(
        self, ip_address: str, port: int, hostname: str | None, reverse_dns: str
    ) -> ServiceResult | None:
        schemes = ["https", "http"] if port in TLS_PORTS else ["http", "https"]
        errors: list[str] = []
        for scheme in schemes:
            result, error = await self._try_scheme(
                ip_address, port, hostname, reverse_dns, scheme
            )
            if result:
                return result
            if error:
                errors.append(f"{scheme}: {error}")
        LOG.debug("Open port %s:%s did not speak HTTP(S): %s", ip_address, port, errors)
        return None

    async def _try_scheme(
        self,
        ip_address: str,
        port: int,
        hostname: str | None,
        reverse_dns: str,
        scheme: str,
    ) -> tuple[ServiceResult | None, str]:
        display_host = hostname or ip_address
        url_host = f"[{display_host}]" if ":" in display_host else display_host
        base_url = f"{scheme}://{url_host}:{port}"
        resolver = FixedResolver(hostname, ip_address) if hostname else None
        ssl_context: ssl.SSLContext | bool | None = None
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            ssl_context = context
        connector = aiohttp.TCPConnector(
            resolver=resolver, ssl=ssl_context, family=socket.AF_INET, limit=1
        )
        timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
        detections: list[Detection] = []
        root_data: dict[str, Any] = {}
        errors: list[str] = []
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": self.config.user_agent, "Accept": "text/html,*/*;q=0.5"},
            ) as session:
                for path in self.config.paths:
                    response_data, error = await self._request_with_retry(
                        session, base_url + path
                    )
                    if error:
                        errors.append(f"{path}: {error}")
                        continue
                    if response_data is None:
                        continue
                    detections.append(
                        detect_php(
                            response_data["headers"],
                            response_data["body"],
                            path,
                            response_data["status"],
                        )
                    )
                    if not root_data or path == "/":
                        root_data = response_data
                if not root_data:
                    return None, "; ".join(errors)
        except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError, OSError) as exc:
            return None, str(exc)

        detection = merge_detections(detections)
        verified_status = "NOT_VERIFIED"
        verified_source = ""
        if self.inventory:
            record = self.inventory.lookup(ip_address, hostname or reverse_dns)
            if record:
                verified_status = record.verified_patch_status or "NOT_VERIFIED"
                verified_source = record.source
                if record.installed_php_version:
                    detection.php_detected = True
                    detection.confidence = "CONFIRMED"
                    detection.version = record.installed_php_version
                    detection.version_source = f"Authenticated inventory: {record.source}"
                    detection.evidence.append("Installed PHP package reported by trusted inventory")
        assessment = assess_php(detection.confidence, detection.version, verified_status)
        tls = root_data.get("tls", {})
        return ServiceResult(
            ip_address=ip_address,
            hostname=hostname or "",
            reverse_dns=reverse_dns,
            port=port,
            protocol=scheme.upper(),
            url=base_url + "/",
            http_status=root_data.get("status"),
            webserver=_header_value(root_data["headers"], "server"),
            redirect_target=_header_value(root_data["headers"], "location"),
            tls_version=tls.get("version", ""),
            tls_cipher=tls.get("cipher", ""),
            tls_cert_subject=tls.get("subject", ""),
            tls_cert_issuer=tls.get("issuer", ""),
            tls_cert_not_after=tls.get("not_after", ""),
            tls_cert_sha256=tls.get("sha256", ""),
            detected_application=detection.application,
            php_detected=detection.php_detected,
            php_confidence=detection.confidence,
            php_version=detection.version,
            php_version_source=detection.version_source,
            required_patch_level=assessment["required"],
            security_assessment=assessment["status"],
            suspected_vulnerability=assessment["suspected"],
            verified_patch_status=verified_status,
            verified_patch_source=verified_source,
            recommended_action=assessment["action"],
            detection_evidence="; ".join(detection.evidence),
            errors="; ".join(errors),
        ), ""

    async def _request_with_retry(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[dict[str, Any] | None, str]:
        last_error = ""
        for attempt in range(self.config.retries + 1):
            try:
                await self.rate_limiter.wait()
                async with session.get(url, allow_redirects=False) as response:
                    transport = response.connection.transport if response.connection else None
                    tls = _tls_info(transport)
                    body_bytes = await response.content.read(MAX_BODY_BYTES + 1)
                    body = body_bytes[:MAX_BODY_BYTES].decode(
                        response.charset or "utf-8", errors="replace"
                    )
                    headers = {key: value for key, value in response.headers.items()}
                    cookies = response.headers.getall("Set-Cookie", [])
                    if cookies:
                        headers["Set-Cookie"] = ", ".join(cookies)
                    return {
                        "status": response.status,
                        "headers": headers,
                        "body": body,
                        "tls": tls,
                    }, ""
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, OSError) as exc:
                last_error = str(exc)
                if attempt < self.config.retries:
                    await asyncio.sleep(0.25 * (2**attempt))
        return None, last_error


def _tls_info(transport: asyncio.Transport | None) -> dict[str, str]:
    if not transport:
        return {}
    ssl_object = transport.get_extra_info("ssl_object")
    if not ssl_object:
        return {}
    cert = ssl_object.getpeercert() or {}
    der = ssl_object.getpeercert(binary_form=True)
    cipher = ssl_object.cipher()
    return {
        "version": ssl_object.version() or "",
        "cipher": cipher[0] if cipher else "",
        "subject": _name_string(cert.get("subject", ())),
        "issuer": _name_string(cert.get("issuer", ())),
        "not_after": cert.get("notAfter", ""),
        "sha256": hashlib.sha256(der).hexdigest() if der else "",
    }


def _name_string(parts: Any) -> str:
    return ", ".join(f"{key}={value}" for group in parts for key, value in group)


def _header_value(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    return next((value for key, value in headers.items() if key.lower() == wanted), "")
