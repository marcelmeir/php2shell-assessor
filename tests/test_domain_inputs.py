import csv
from pathlib import Path

from openpyxl import Workbook

from php2shell.domain_inputs import load_domain_entries, prepare_domain_list
from php2shell.targets import TargetSet


def test_csv_domain_list_is_scoped_and_reported(tmp_path: Path):
    source = tmp_path / "domains.csv"
    source.write_text(
        "Domain,IP address,Status\n"
        "app.example.edu,192.0.2.10,active\n"
        "external.example.edu,,active\n"
        "missing.example.edu,,historical\n"
        "*.example.edu,,wildcard\n",
        encoding="utf-8",
    )
    answers = {
        "app.example.edu": (["192.0.2.10"], ""),
        "external.example.edu": (["203.0.113.5"], ""),
        "missing.example.edu": ([], "not found"),
    }
    prepared = prepare_domain_list(
        source,
        TargetSet(["192.0.2.0/24"]),
        tmp_path / "out",
        resolver=lambda name: answers[name],
    )
    assert prepared.hostnames == {"192.0.2.10": ["app.example.edu"]}
    assert prepared.in_scope_names == 1
    assert prepared.outside_scope_names == 1
    assert prepared.unresolved_names == 1
    assert prepared.skipped_wildcards == 1
    with prepared.report_path.open(encoding="utf-8-sig") as handle:
        dispositions = {row["dns_name"]: row["disposition"] for row in csv.DictReader(handle)}
    assert dispositions["external.example.edu"] == "OUTSIDE_SCOPE"
    assert dispositions["*.example.edu"] == "WILDCARD_SKIPPED"


def test_xlsx_finds_header_below_title_rows(tmp_path: Path):
    source = tmp_path / "domains.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["Domain inventory"])
    sheet.append([])
    sheet.append(["FQDN", "IP addresses", "DNS status"])
    sheet.append(["portal.example.edu", "192.0.2.20; 192.0.2.21", "CURRENT"])
    workbook.save(source)
    entries, invalid = load_domain_entries(source)
    assert invalid == 0
    assert entries[0].name == "portal.example.edu"
    assert entries[0].supplied_ips == {"192.0.2.20", "192.0.2.21"}
    assert entries[0].status == "CURRENT"


def test_domain_resolution_can_be_disabled(tmp_path: Path):
    source = tmp_path / "domains.txt"
    source.write_text("192.0.2.30 static.example.edu\nname-only.example.edu\n", encoding="utf-8")
    prepared = prepare_domain_list(
        source,
        TargetSet(["192.0.2.0/24"]),
        tmp_path / "out",
        resolve_dns=False,
    )
    assert prepared.hostnames == {"192.0.2.30": ["static.example.edu"]}
    assert prepared.unresolved_names == 1
