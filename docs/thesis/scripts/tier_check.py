"""
tier_check.py - manual check of the urgency tiers (RQ2, Section 5.6 / 6.3).

For every correlation match judged to apply (applies = Y), the urgency tier is
recomputed with the same rule as the workflow (Table H.5, prioritisation.urgency_tier),
but with inputs an analyst takes from the sources rather than from the snapshot:

  vendor basis  CVSS v3.1 score and vector from the vendor advisory (Siemens ProductCERT,
                also published in NVD as the CNA 'Secondary' score), fix availability from
                the advisory's remediation section. This is the reference: tier_manual.
  NVD basis     NVD's own CVSS v3.1 score (source nvd@nist.gov), same fix availability.
                Written to tier_nvd_basis, as a sensitivity check only.

KEV and EPSS are taken from the row (the snapshot values), so the only inputs that
change are the CVSS score and the fix availability.

The analyst inputs are in ADVISORY below, one entry per CVE, with their source. Check
each value against the advisory before you rely on the output.

Analysis only: added after v-eval-final, changes nothing in the engine.

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/tier_check.py --checked docs/thesis/results/final/correlation_matches_checked.csv
then
    python docs/thesis/scripts/evaluate_correlation.py --summary docs/thesis/results/final/correlation_matches_checked.csv --reference docs/thesis/results/final/reference_vulns.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "backend"))

from app.engine.prioritisation import urgency_tier  # noqa: E402

# Analyst inputs, read from the sources on 10 October 2026
ADVISORY = {
    "CVE-2022-30694": {
        "advisory": "SSA-478960",
        "vendor_cvss": 6.5,
        "vendor_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "nvd_cvss": 3.5,
        "nvd_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
        "fix": "V3.2.19 (update firmware)",
    },
    "CVE-2019-13940": {
        "advisory": "SSA-431678",
        "vendor_cvss": 5.3,
        "vendor_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "nvd_cvss": 7.5,
        "nvd_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "fix": "V3.X.17 (update firmware)",
    },
}
NEW_COLUMNS = [
    "cvss_vendor",
    "cvss_nvd",
    "snapshot_cvss_source",
    "fix_advisory",
    "tier_manual_reason",
    "tier_nvd_basis",
]


def source_of(score: str, a: dict) -> str:
    try:
        s = float(score)
    except ValueError:
        return "unknown"
    if s == a["vendor_cvss"] and s != a["nvd_cvss"]:
        return "vendor (CNA)"
    if s == a["nvd_cvss"] and s != a["vendor_cvss"]:
        return "NVD"
    return "same in both" if s == a["vendor_cvss"] == a["nvd_cvss"] else "neither"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--checked", required=True, help="correlation_matches_checked.csv")
    args = ap.parse_args()
    path = Path(args.checked)
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
    fields = list(rows[0].keys())
    fields += [c for c in NEW_COLUMNS if c not in fields]

    agree_v = agree_n = n = 0
    for r in rows:
        for c in NEW_COLUMNS:
            r.setdefault(c, "")
        if (r.get("applies") or "").strip().upper() != "Y":
            r["tier_manual"] = ""
            continue
        a = ADVISORY.get(r["cve_id"].strip().upper())
        if a is None:
            print(f"no analyst inputs for {r['cve_id']}: add it to ADVISORY")
            continue
        kev = (r.get("kev") or "").strip().upper() == "Y"
        epss = float(r["epss"]) if (r.get("epss") or "").strip() else None
        fix = bool(a["fix"])
        tier_v, why_v = urgency_tier(
            a["vendor_cvss"], a["vendor_vector"], kev, epss, fix
        )
        tier_n, _ = urgency_tier(a["nvd_cvss"], a["nvd_vector"], kev, epss, fix)
        r.update(
            {
                "tier_manual": tier_v,
                "tier_manual_reason": why_v,
                "tier_nvd_basis": tier_n,
                "cvss_vendor": a["vendor_cvss"],
                "cvss_nvd": a["nvd_cvss"],
                "snapshot_cvss_source": source_of(r.get("cvss", ""), a),
                "fix_advisory": f"{a['advisory']}: {a['fix']}",
            }
        )
        n += 1
        agree_v += tier_v == r["urgency_tier"]
        agree_n += tier_n == r["urgency_tier"]
        print(
            f"{r['ip']:15s} {r['cve_id']:15s} workflow {r['urgency_tier']:10s} "
            f"(CVSS {r['cvss']}, {r['snapshot_cvss_source']}, fix in NVD: {r.get('fixed_in') or 'none'})"
        )
        print(
            f"{'':31s} vendor   {tier_v:10s} (CVSS {a['vendor_cvss']}, fix {a['fix']})   "
            f"NVD basis {tier_n} (CVSS {a['nvd_cvss']})"
        )

    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"\nTier agreement, vendor basis (tier_manual): {agree_v}/{n}")
    print(f"Tier agreement, NVD basis (sensitivity):    {agree_n}/{n}")
    print(f"Written: {path}")


if __name__ == "__main__":
    main()
