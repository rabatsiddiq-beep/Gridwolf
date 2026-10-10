"""Tests for the Table 4.3 urgency tiers and their use in device correlation.

CVE ids are fake (CVE-TEST-*); no real vulnerability is asserted.
"""

from __future__ import annotations

import gzip
import json

import pytest

from app.engine.cve_lookup import CVELookup, version_affected
from app.engine.prioritisation import attack_vector, urgency_tier
from app.engine.vuln_feed import Advisory, VulnFeedEngine


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "network"),
        ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "physical"),
        ("AV:A/AC:L/Au:N/C:P/I:P/A:P", "adjacent"),
        ("", ""),
        (None, ""),
    ],
)
def test_attack_vector(vector, expected):
    assert attack_vector(vector) == expected


NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
PHY = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.parametrize(
    "args,tier",
    [
        (dict(cvss=5.0, vector=NET, kev=True), "act_now"),  # KEV beats a medium score
        (dict(cvss=9.8, vector=NET), "act_now"),
        (dict(cvss=9.8, vector=""), "act_now"),  # unstated vector treated as network
        (dict(cvss=9.8, vector=PHY), "plan_patch"),  # physical: not act now, but >= 8.0
        (dict(cvss=4.3, vector=NET, epss=0.25), "act_now"),
        (dict(cvss=4.3, vector=NET, epss=0.10), "monitor"),  # threshold is strictly above
        (dict(cvss=7.5, vector=NET, fix_available=True), "plan_patch"),
        (dict(cvss=7.5, vector=NET), "monitor"),  # 7.0-7.9 without a fix
        (dict(cvss=8.1, vector=NET), "plan_patch"),
        (dict(cvss=3.9, vector=NET), "low_risk"),
        (dict(cvss=None), "low_risk"),
    ],
)
def test_table_4_3(args, tier):
    assert urgency_tier(**args)[0] == tier


def test_feed_and_correlation_share_the_rules():
    adv = Advisory(cvss_score=7.5, cvss_vector=NET, patch_available=True)
    assert VulnFeedEngine._compute_urgency_tier(adv) == "plan_patch"
    adv = Advisory(cvss_score=5.0, kev_listed=True)
    assert VulnFeedEngine._compute_urgency_tier(adv) == "act_now"


def test_hardware_cpe_without_version_cannot_be_checked():
    assert version_affected("V3.2.7", {"version": "-"}) is None
    assert version_affected("V3.2.7", {"version": "*"}) is True


def _rec(cve_id, product, score, vector=NET, kev=False, epss=None, **rng):
    return {
        "cve_id": cve_id,
        "published": "2024-01-01",
        "description": "test",
        "cvss_score": score,
        "severity": "",
        "cvss_vector": vector,
        "cwe": [],
        "affected": [{"vendor": "siemens", "product": product, "version": "*", **rng}],
        "kev": kev,
        "kev_date_added": "",
        "epss": epss,
        "epss_percentile": None,
    }


@pytest.fixture()
def lookup(tmp_path):
    product = "simatic_s7-300_cpu_315-2_pn/dp_firmware"
    recs = [
        _rec("CVE-TEST-0101", product, 7.5, end_excl="3.2.17"),  # fixed later: plan_patch
        _rec("CVE-TEST-0102", product, 5.3, kev=True),  # KEV: act_now
        _rec("CVE-TEST-0103", product, 6.5),  # monitor
        _rec("CVE-TEST-0104", product, 9.8, end_excl="3.2.5"),  # firmware already fixed
    ]
    path = tmp_path / "snap.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump({"meta": {"built_utc": "2026-10-10T00:00:00Z"}, "cves": recs}, fh)
    return CVELookup(snapshot_path=str(path))


def test_correlation_assigns_tiers_and_counts(lookup):
    corr = lookup.correlate("Siemens AG", "CPU 315-2 PN/DP (6ES7 315-2EH14-0AB0)", "V3.2.7")
    tiers = {m["cve_id"]: m["urgency_tier"] for m in corr["matches"]}
    assert tiers == {
        "CVE-TEST-0101": "plan_patch",
        "CVE-TEST-0102": "act_now",
        "CVE-TEST-0103": "monitor",
    }
    assert corr["urgency_counts"] == {"act_now": 1, "plan_patch": 1, "monitor": 1, "low_risk": 0}
    first = corr["matches"][0]
    assert first["cve_id"] == "CVE-TEST-0102"  # ranking unchanged: KEV first
    assert first["tier_reason"] == "listed in CISA KEV"
    fixed = next(m for m in corr["matches"] if m["cve_id"] == "CVE-TEST-0101")
    assert fixed["match"]["fixed_in"] == "3.2.17"


def test_vendor_only_device_gets_no_tiers(lookup):
    corr = lookup.correlate("Siemens AG", None, None)
    assert corr["tier"] == "B" and corr["matches"] == []
    assert sum(corr["urgency_counts"].values()) == 0
