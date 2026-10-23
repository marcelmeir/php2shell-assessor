from __future__ import annotations

from packaging.version import InvalidVersion, Version

PATCH_LEVELS = {
    (8, 5): Version("8.5.12"),
    (8, 4): Version("8.4.27"),
    (8, 3): Version("8.3.36"),
    (8, 2): Version("8.2.35"),
}


def assess_php(
    confidence: str,
    version_text: str,
    verified_patch_status: str = "NOT_VERIFIED",
) -> dict[str, str]:
    if confidence == "UNKNOWN":
        return {
            "required": "",
            "status": "WEB_SERVER_FOUND",
            "suspected": "UNKNOWN",
            "action": "No reliable PHP evidence; retain for asset review if expected.",
        }
    if confidence != "CONFIRMED" and not version_text:
        return {
            "required": "",
            "status": "PHP_SUSPECTED",
            "suspected": "UNKNOWN",
            "action": "Manually confirm PHP use and determine the installed package version.",
        }
    if not version_text:
        return {
            "required": "",
            "status": "PHP_VERSION_UNKNOWN",
            "suspected": "UNKNOWN",
            "action": "Use authenticated inventory to determine PHP packages and patch status.",
        }
    try:
        version = Version(version_text)
    except InvalidVersion:
        return {
            "required": "",
            "status": "PHP_VERSION_UNKNOWN",
            "suspected": "UNKNOWN",
            "action": "Version was not parseable; verify with authenticated inventory.",
        }
    branch = (version.major, version.minor)
    if branch in PATCH_LEVELS:
        required = PATCH_LEVELS[branch]
        below = version < required
        status = "CRITICAL" if below else "PATCH_LEVEL_DETECTED"
        suspected = "YES" if below else "NO"
        action = (
            f"Urgently verify distro package/backports and update to a vendor-fixed build "
            f"(upstream baseline {required} or newer)."
            if below
            else "Confirm the installed vendor package and security update through authenticated inventory."
        )
    elif branch < (8, 2):
        required = Version("8.2.35")
        status, suspected = "CRITICAL", "YES"
        action = "Unsupported/legacy PHP branch: migrate to a supported, vendor-patched release and verify inventory."
    else:
        required = None
        status, suspected = "PHP_VERSION_UNKNOWN", "UNKNOWN"
        action = "No baseline is configured for this PHP branch; perform vendor-specific manual review."
    if verified_patch_status.upper() == "PATCHED":
        suspected = "OVERRIDDEN_BY_VERIFIED_INVENTORY"
        action = "Verified inventory reports a patched package; retain the evidence for audit."
    return {
        "required": str(required) if required else "",
        "status": status,
        "suspected": suspected,
        "action": action,
    }
