from pathlib import Path

import pytest

from php2shell.targets import TargetSet, load_authorized_hostnames


def test_target_set_is_lazy_deduplicated_and_excluded():
    targets = TargetSet(
        ["192.0.2.0/29", "192.0.2.2"], ["192.0.2.3", "192.0.2.4"]
    )
    assert list(targets) == ["192.0.2.1", "192.0.2.2", "192.0.2.5", "192.0.2.6"]
    assert targets.count == 4


def test_hostname_mapping_must_remain_in_scope(tmp_path: Path):
    mapping = tmp_path / "hosts.txt"
    mapping.write_text("198.51.100.5 app.example.edu\n", encoding="utf-8")
    with pytest.raises(ValueError, match="outside"):
        load_authorized_hostnames(mapping, TargetSet(["192.0.2.0/24"]))
