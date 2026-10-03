"""Tests for snapshot-based CVE correlation (no network, synthetic fixture data).

The fixture CVE ids are deliberately fake (CVE-TEST-*) so the tests never assert
anything about real vulnerabilities.
"""

from __future__ import annotations

import gzip
import json

import pytest

from app.engine.cve_lookup import (
    CVELookup,
    normalise_vendor,
    product_candidates,
    version_affected,
)
from app.engine.vuln_snapshot import apply_epss, apply_kev, parse_nvd_item


def _nvd_item(cve_id, criteria, score=7.5, **ranges):
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-01-01T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": f"Test vulnerability {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "baseScore": score,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N",
                        },
                    }
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-20"}]}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "negate": False,
                            "cpeMatch": [{"vulnerable": True, "criteria": criteria, **ranges}],
                        }
                    ]
                }
            ],
        }
    }


S7_315 = "cpe:2.3:o:siemens:simatic_s7-300_cpu_315-2_pn\\/dp_firmware:*:*:*:*:*:*:*:*"
S7_1500 = "cpe:2.3:o:siemens:simatic_s7-1500_cpu_firmware:*:*:*:*:*:*:*:*"
NAE = "cpe:2.3:o:johnsoncontrols:ms-nae4510-2_firmware:*:*:*:*:*:*:*:*"
WIN = "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"


@pytest.fixture()
def snapshot_path(tmp_path):
    items = [
        _nvd_item("CVE-TEST-0001", S7_315, 7.5, versionEndExcluding="3.2.17"),
        _nvd_item("CVE-TEST-0002", S7_315, 9.8, versionEndExcluding="3.2.5"),
        _nvd_item("CVE-TEST-0003", S7_1500, 9.8),
        _nvd_item("CVE-TEST-0004", NAE, 6.5, versionEndIncluding="6.0"),
        _nvd_item("CVE-TEST-0005", S7_315, 5.3),
        _nvd_item("CVE-TEST-0006", WIN, 9.8),
    ]
    recs = [r for r in (parse_nvd_item(i) for i in items) if r]
    apply_kev(recs, {"vulnerabilities": [{"cveID": "CVE-TEST-0005", "dateAdded": "2024-02-01"}]})
    apply_epss(
        recs,
        [
            {"cve": "CVE-TEST-0001", "epss": "0.02", "percentile": "0.80"},
            {"cve": "CVE-TEST-0005", "epss": "0.01", "percentile": "0.70"},
        ],
    )
    path = tmp_path / "snap.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump({"meta": {"built_utc": "2026-10-06T00:00:00Z"}, "cves": recs}, fh)
    return path


def test_parse_keeps_only_in_scope_vendors():
    assert parse_nvd_item(_nvd_item("CVE-TEST-0006", WIN)) is None
    rec = parse_nvd_item(_nvd_item("CVE-TEST-0001", S7_315, versionEndExcluding="3.2.17"))
    assert rec["affected"][0]["product"] == "simatic_s7-300_cpu_315-2_pn/dp_firmware"
    assert rec["cvss_score"] == 7.5 and rec["cwe"] == ["CWE-20"]


@pytest.mark.parametrize(
    "vendor,expected",
    [
        ("Siemens AG", "siemens"),
        ("Siemens AG,", "siemens"),
        ("Rockwell Automation", "rockwellautomation"),
        ("Prosoft / Allen-Bradley", "rockwellautomation"),
        ("Johnson Controls (JCI, BACnet vendor-id 5)", "johnsoncontrols"),
        ("Sick Ag", "sick"),
        ("Elau Ag", None),
        ("Hewlett Packard", None),
        (None, None),
    ],
)
def test_normalise_vendor(vendor, expected):
    assert normalise_vendor(vendor) == expected


def test_product_candidates_split_name_and_order_number():
    assert product_candidates("CPU 315-2 PN/DP (6ES7 315-2EH14-0AB0)") == [
        "cpu3152pndp",
        "6es73152eh140ab0",
    ]


@pytest.mark.parametrize(
    "fw,rng,expected",
    [
        ("V3.2.7", {"version": "*", "end_excl": "3.2.17"}, True),
        ("V3.2.7", {"version": "*", "end_excl": "3.2.5"}, False),
        ("V3.2.7", {"version": "*", "start_incl": "3.3", "end_excl": "4.0"}, False),
        ("5.1.0.4400", {"version": "*", "end_incl": "6.0"}, True),
        ("V3.2", {"version": "3.2.0"}, True),
        (None, {"version": "*", "end_excl": "3.2.17"}, None),
    ],
)
def test_version_affected(fw, rng, expected):
    assert version_affected(fw, rng) is expected


def test_tier_a_matches_product_and_firmware_and_ranks_kev_first(snapshot_path):
    lookup = CVELookup(snapshot_path=str(snapshot_path))
    corr = lookup.correlate("Siemens AG", "CPU 315-2 PN/DP (6ES7 315-2EH14-0AB0)", "V3.2.7")
    assert corr["tier"] == "A"
    ids = [m["cve_id"] for m in corr["matches"]]
    # 0002 is fixed in 3.2.5 (firmware is newer); 0003 is a different product
    assert ids == ["CVE-TEST-0005", "CVE-TEST-0001"]  # KEV first, then EPSS
    assert corr["matches"][0]["kev"] is True


def test_product_without_firmware_is_tier_a_minus(snapshot_path):
    lookup = CVELookup(snapshot_path=str(snapshot_path))
    corr = lookup.correlate("Siemens AG", "CPU 315-2 PN/DP", None)
    assert corr["tier"] == "A-"
    assert {m["match"]["version_check"] for m in corr["matches"]} == {"unknown"}


def test_vendor_only_is_tier_b_without_per_cve_claims(snapshot_path):
    lookup = CVELookup(snapshot_path=str(snapshot_path))
    corr = lookup.correlate("Siemens AG", None, None)
    assert corr["tier"] == "B"
    assert corr["matches"] == []
    assert corr["vendor_cve_count"] == 4 and corr["vendor_kev_count"] == 1


def test_device_type_is_never_used_as_product(snapshot_path):
    lookup = CVELookup(snapshot_path=str(snapshot_path))
    assert lookup.match_device("Siemens AG", None, None) == []
    assert lookup.correlate("Hewlett Packard", "HMI", None)["tier"] == "C"


def test_bacnet_identity_matches(snapshot_path):
    lookup = CVELookup(snapshot_path=str(snapshot_path))
    corr = lookup.correlate("Johnson Controls (JCI)", "MS-NAE4510-2", "5.1.0.4400")
    assert [m["cve_id"] for m in corr["matches"]] == ["CVE-TEST-0004"]


def test_missing_snapshot_reports_nothing(tmp_path):
    lookup = CVELookup(snapshot_path=str(tmp_path / "does-not-exist.json.gz"))
    assert lookup.cves == []
    assert lookup.correlate("Siemens AG", "CPU 315-2 PN/DP", "V3.2.7")["matches"] == []
