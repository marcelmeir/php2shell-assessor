from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class HostResult:
    ip_address: str
    reverse_dns: str = ""
    reachable: bool = False
    web_service_count: int = 0
    status: str = "NO_WEB_SERVICE"
    error: str = ""
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ServiceResult:
    ip_address: str
    hostname: str
    reverse_dns: str
    port: int
    protocol: str
    url: str
    reachable: bool = True
    http_status: int | None = None
    webserver: str = ""
    redirect_target: str = ""
    tls_version: str = ""
    tls_cipher: str = ""
    tls_cert_subject: str = ""
    tls_cert_issuer: str = ""
    tls_cert_not_after: str = ""
    tls_cert_sha256: str = ""
    detected_application: str = ""
    php_detected: bool = False
    php_confidence: str = "UNKNOWN"
    php_version: str = ""
    php_version_source: str = ""
    required_patch_level: str = ""
    security_assessment: str = "WEB_SERVER_FOUND"
    suspected_vulnerability: str = "UNKNOWN"
    verified_patch_status: str = "NOT_VERIFIED"
    verified_patch_source: str = ""
    recommended_action: str = ""
    detection_evidence: str = ""
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    errors: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
