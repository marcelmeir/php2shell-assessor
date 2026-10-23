from pathlib import Path

import pytest

from run_scan import config_to_args


def test_toml_config_translation_resolves_relative_paths(tmp_path: Path):
    args = config_to_args(
        {
            "scope": {
                "authorization_confirmed": True,
                "networks": ["192.0.2.0/24"],
                "domain_list": "domains.xlsx",
                "resolve_domains": False,
            },
            "scan": {
                "ports": [80, 443],
                "paths": ["/"],
                "concurrency": 10,
                "dry_run": True,
            },
            "report": {"output": "reports/run-1"},
        },
        tmp_path,
    )
    assert args[:2] == ["--network", "192.0.2.0/24"]
    assert str(tmp_path / "domains.xlsx") in args
    assert "--no-domain-resolution" in args
    assert "--dry-run" in args
    assert args[args.index("--concurrency") + 1] == "10"
    assert args[args.index("--output") + 1] == str(tmp_path / "reports/run-1")


def test_unknown_config_key_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="netwroks"):
        config_to_args(
            {"scope": {"authorization_confirmed": True, "netwroks": ["192.0.2.0/24"]}},
            tmp_path,
        )
