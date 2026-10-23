import pytest

from php2shell.assessment import assess_php


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("8.5.11", "CRITICAL"),
        ("8.5.12", "PATCH_LEVEL_DETECTED"),
        ("8.4.26", "CRITICAL"),
        ("8.4.27", "PATCH_LEVEL_DETECTED"),
        ("8.3.35", "CRITICAL"),
        ("8.3.36", "PATCH_LEVEL_DETECTED"),
        ("8.2.34", "CRITICAL"),
        ("8.2.35", "PATCH_LEVEL_DETECTED"),
        ("8.1.99", "CRITICAL"),
    ],
)
def test_patch_boundaries(version, expected):
    result = assess_php("CONFIRMED", version)
    assert result["status"] == expected


def test_unknown_version_needs_manual_review():
    assert assess_php("CONFIRMED", "")["status"] == "PHP_VERSION_UNKNOWN"


def test_suspected_php_without_version():
    assert assess_php("HIGH", "")["status"] == "PHP_SUSPECTED"


def test_verified_inventory_does_not_rewrite_observed_version_assessment():
    result = assess_php("CONFIRMED", "8.2.20", "PATCHED")
    assert result["status"] == "CRITICAL"
    assert result["suspected"] == "OVERRIDDEN_BY_VERIFIED_INVENTORY"
