from __future__ import annotations

import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Mapping

PHP_VERSION_RE = re.compile(r"PHP[/ ]([0-9]+(?:\.[0-9]+){1,2})", re.I)


@dataclass(slots=True)
class Detection:
    confidence: str = "UNKNOWN"
    php_detected: bool = False
    version: str = ""
    version_source: str = ""
    application: str = ""
    evidence: list[str] = field(default_factory=list)


APP_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("WordPress", ("wp-content/", "wp-includes/", "wordpress_logged_in_")),
    ("Drupal", ("drupal-settings-json", "sites/default/files", "x-drupal-cache")),
    ("Joomla", ("/media/system/js/", "joomla!", "joomla_user_state")),
    ("TYPO3", ("typo3temp/", "typo3/cms", "fe_typo_user")),
    ("Nextcloud", ("nextcloud", "oc_sessionpassphrase", "nc_sameSiteCookielax")),
    ("MediaWiki", ("mediawiki", "mw.config", "mediawiki_session")),
    ("Moodle", ("moodlesession", "moodle", "theme/styles.php")),
)


def detect_php(
    headers: Mapping[str, str],
    body: str,
    requested_path: str = "/",
    http_status: int = 200,
) -> Detection:
    normalized_headers = {name.lower(): value for name, value in headers.items()}
    evidence: list[str] = []
    direct = False
    strong = 0
    weak = 0
    version = ""
    source = ""

    powered = normalized_headers.get("x-powered-by", "")
    server = normalized_headers.get("server", "")
    for header_name, value in (("X-Powered-By", powered), ("Server", server)):
        if "php" in value.lower():
            direct = True
            evidence.append(f"{header_name} contains PHP")
            match = PHP_VERSION_RE.search(value)
            if match and not version:
                version, source = match.group(1), f"HTTP header {header_name}"

    cookie_names: set[str] = set()
    raw_cookies = normalized_headers.get("set-cookie", "")
    if raw_cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookies)
            cookie_names = {name.lower() for name in cookie.keys()}
        except Exception:
            cookie_names = set(re.findall(r"(?:^|,)\s*([^=;, ]+)=", raw_cookies.lower()))
    if "phpsessid" in cookie_names:
        strong += 1
        evidence.append("PHPSESSID cookie observed")

    haystack = (body[:262144] + "\n" + "\n".join(f"{k}:{v}" for k, v in headers.items())).lower()
    application = ""
    for app, signatures in APP_SIGNATURES:
        if any(signature.lower() in haystack for signature in signatures):
            application = app
            strong += 2
            evidence.append(f"Public {app} signature observed")
            break

    if requested_path.lower().endswith(".php") and 200 <= http_status < 400:
        weak += 1
        evidence.append(f"PHP path responded: {requested_path}")
    if "x-pingback" in {name.lower() for name in headers}:
        weak += 1
        evidence.append("X-Pingback header observed")

    if direct:
        confidence = "CONFIRMED"
    elif strong >= 2 or (strong >= 1 and weak >= 1):
        confidence = "HIGH"
    elif strong >= 1 or weak >= 2:
        confidence = "MEDIUM"
    elif weak:
        confidence = "LOW"
    else:
        confidence = "UNKNOWN"
    return Detection(
        confidence=confidence,
        php_detected=direct,
        version=version,
        version_source=source,
        application=application,
        evidence=evidence,
    )


def merge_detections(items: list[Detection]) -> Detection:
    rank = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CONFIRMED": 4}
    if not items:
        return Detection()
    best = max(items, key=lambda item: rank[item.confidence])
    evidence = list(dict.fromkeys(part for item in items for part in item.evidence))
    versioned = next((item for item in items if item.version), best)
    app = next((item.application for item in items if item.application), "")
    return Detection(
        confidence=best.confidence,
        php_detected=any(item.php_detected for item in items),
        version=versioned.version,
        version_source=versioned.version_source,
        application=app,
        evidence=evidence,
    )
