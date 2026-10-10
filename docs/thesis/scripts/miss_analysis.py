"""
miss_analysis.py - why did the workflow miss reference CVEs? (Chapter 5.6 / 6.3)

For every CVE in the reference set that the workflow did not report for a device,
looks it up in the committed vulnerability snapshot and classifies the miss:

  not_in_snapshot    the CVE has no firmware/hardware (CPE part o/h) entry for an
                     in-scope vendor, so the snapshot never held it (e.g. listed
                     only as application software, CPE part a)
  product_name       the CVE is in the snapshot, but none of its CPE product names
                     contains the device's product name or order number (e.g. a
                     family-level name such as simatic_s7-300_cpu_firmware)
  version_range      a CPE product name matched, but the stated version range
                     excludes the device firmware

Each product_name miss is split further (column 'detail'):
  near_name          NVD names the same model differently (e.g. "cpu_315-2_pn"
                     for a "CPU 315-2 PN/DP")
  family_name        NVD lists only the product family (e.g. "simatic_s7-300_cpu_firmware")
  not_listed         NVD lists other products only (e.g. PROFINET stack components),
                     although the vendor advisory names this device or its family

Analysis only: it reads the snapshot and changes nothing in the artefact.

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/miss_analysis.py --matches <checked matches CSV> --reference <reference_vulns.csv> --out <folder>
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "backend"))

from app.engine.cve_lookup import (  # noqa: E402
    _norm,
    normalise_vendor,
    product_candidates,
    version_affected,
)
from app.engine.vuln_snapshot import load_snapshot  # noqa: E402

DEVICES = {  # ip -> (vendor, product, firmware), as identified by the workflow
    "134.217.61.211": ("Siemens AG", "CPU 315-2 PN/DP (6ES7 315-2EH14-0AB0)", "V3.2.7"),
    "192.168.1.40": ("Siemens AG", "IM151-8 PN/DP CPU (6ES7 151-8AB01-0AB0)", "V3.2.6"),
    "10.1.1.165": ("JCI", "MS-NAE4510-2", "5.1.0.4400"),
}
# Normalised model core and family stems, used only to explain product_name misses
# "im1518", not "1518": the bare digits also occur in S7-1500 "cpu_1518" product names
MODEL_CORE = {"134.217.61.211": "3152pn", "192.168.1.40": "im1518", "10.1.1.165": "nae45"}
FAMILY = {
    "134.217.61.211": ("s7300",),
    "192.168.1.40": ("s7300", "et200s"),
    "10.1.1.165": ("nae", "metasys"),
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matches", required=True)
    ap.add_argument("--reference", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    by_id = {r["cve_id"]: r for r in load_snapshot()["cves"]}
    found = {
        (r["ip"].strip(), r["cve_id"].strip().upper())
        for r in csv.DictReader(open(args.matches, encoding="utf-8-sig"))
        if (r.get("applies") or "").strip().upper() == "Y"
    }
    rows, reasons = [], Counter()
    for ref in csv.DictReader(open(args.reference, encoding="utf-8-sig")):
        ip, cve = ref["ip"].strip(), ref["cve_id"].strip().upper()
        if (ip, cve) in found:
            continue
        vendor, product, firmware = DEVICES[ip]
        nvd_vendor = normalise_vendor(vendor)
        cands = product_candidates(product)
        rec = by_id.get(cve)
        products = sorted({a["product"] for a in rec["affected"]}) if rec else []
        detail = ""
        if rec is None:
            reason = "not_in_snapshot"
        else:
            named = [
                a
                for a in rec["affected"]
                if a["vendor"] == nvd_vendor and any(c in _norm(a["product"]) for c in cands)
            ]
            if not named:
                reason = "product_name"
                vendor_products = [
                    _norm(a["product"]) for a in rec["affected"] if a["vendor"] == nvd_vendor
                ]
                if any(MODEL_CORE[ip] in p for p in vendor_products):
                    detail = "near_name"
                elif any(stem in p for p in vendor_products for stem in FAMILY[ip]):
                    detail = "family_name"
                else:
                    detail = "not_listed"
            elif all(version_affected(firmware, a) is False for a in named):
                reason = "version_range"
            else:
                reason = "other"
        reasons[reason + (f"/{detail}" if detail else "")] += 1
        rows.append([ip, cve, reason, detail, "; ".join(products)])

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "missed_reference_cves.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "cve_id", "reason", "detail", "snapshot_cpe_products"])
        w.writerows(rows)
    print(
        f"{len(rows)} missed reference CVEs: "
        + ", ".join(f"{k} {v}" for k, v in reasons.most_common())
    )
    print(f"Written: {out / 'missed_reference_cves.csv'}")


if __name__ == "__main__":
    main()
