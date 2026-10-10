"""
evaluate_correlation.py - vulnerability correlation and prioritisation (RQ2).

Mode 1 (default): correlate every device in an engine run with the committed
vulnerability snapshot and export the results for manual checking.

    python docs/thesis/scripts/evaluate_correlation.py --results docs/thesis/results/<label>

  writes, in the results folder:
    correlation_devices.csv  one row per device: identity tier (A, A-, B, C), number
                             of matches, vendor exposure and urgency-tier counts
    correlation_matches.csv  one row per device x CVE match (tiers A and A-), with
                             empty columns for the manual check: advisory_id,
                             applies (Y/N), reason, checked_on, tier_manual
    correlation_summary.txt  snapshot date and hash check, and headline counts

Mode 2: summarise the manual check (Week 3).

    python docs/thesis/scripts/evaluate_correlation.py --summary <checked matches CSV>
        [--reference <reference_vulns.csv>]

  precision = applies Y / rows checked; recall = reference CVEs matched / reference
  CVEs (keyed by device IP and CVE id); tier agreement = tier_manual equal to the
  workflow's urgency tier. Each proportion is given with a 95% Wilson interval.

Aggregates use the independent captures only (codebook R8).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from math import sqrt
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "backend"))

from app.engine.cve_lookup import CVELookup  # noqa: E402
from app.engine.prioritisation import TIERS  # noqa: E402
from app.engine.vuln_snapshot import DEFAULT_SNAPSHOT  # noqa: E402

SUBSETS = {"ModbusTCP.pcap", "EthernetIP-CIP.pcap"}
MANUAL_COLUMNS = ["advisory_id", "applies", "reason", "checked_on", "tier_manual"]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def fmt(k: int, n: int) -> str:
    if n == 0:
        return "-/0"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {k / n:.3f} (95% CI {lo:.3f}-{hi:.3f})"


def snapshot_check(path: Path) -> str:
    if not path.exists():
        return f"MISSING: {path}"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    meta = path.with_name(path.name.replace(".json.gz", ".meta.json"))
    if not meta.exists():
        return f"sha256 {digest} (no meta file to compare)"
    expected = json.loads(meta.read_text(encoding="utf-8")).get("sha256", "")
    status = "OK" if digest == expected else f"MISMATCH (meta says {expected})"
    return f"sha256 {digest} {status}"


def correlate(results: Path, snapshot: Path) -> None:
    lookup = CVELookup(snapshot_path=str(snapshot))
    dev_rows, match_rows = [], []
    for f in sorted(results.glob("*.json")):
        run = json.loads(f.read_text(encoding="utf-8"))
        if "devices" not in run:
            continue
        cap = run["capture"]
        subset = "subset" if cap in SUBSETS else "independent"
        for d in run["devices"]:
            corr = lookup.correlate(d.get("vendor"), d.get("product"), d.get("firmware"))
            base = [cap, subset, d["ip"], d.get("vendor") or "", d.get("product") or ""]
            base += [d.get("firmware") or "", corr["tier"]]
            counts = corr["urgency_counts"]
            dev_rows.append(
                base
                + [corr["nvd_vendor"] or "", len(corr["matches"])]
                + [corr["vendor_cve_count"], corr["vendor_kev_count"]]
                + [counts[t] for t in TIERS]
            )
            for m in corr["matches"]:
                match_rows.append(
                    base
                    + [
                        m["cve_id"],
                        m["match"]["cpe_product"],
                        m["match"]["cpe_version"],
                        m["match"]["version_check"],
                        m["match"]["fixed_in"],
                        m["cvss_score"],
                        m["severity"],
                        m["cvss_vector"],
                        "Y" if m["kev"] else "N",
                        "" if m["epss"] is None else m["epss"],
                        "" if m["epss_percentile"] is None else m["epss_percentile"],
                        m["urgency_tier"],
                        m["tier_reason"],
                        m["published"],
                    ]
                    + [""] * len(MANUAL_COLUMNS)
                )

    head = ["capture", "set", "ip", "vendor", "product", "firmware", "identity_tier"]
    with open(results / "correlation_devices.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            head + ["nvd_vendor", "matches", "vendor_cve_count", "vendor_kev_count"] + list(TIERS)
        )
        w.writerows(dev_rows)
    with open(results / "correlation_matches.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            head
            + ["cve_id", "cpe_product", "cpe_version", "version_check", "fixed_in"]
            + ["cvss", "severity", "cvss_vector", "kev", "epss", "epss_percentile"]
            + ["urgency_tier", "tier_reason", "published"]
            + MANUAL_COLUMNS
        )
        w.writerows(match_rows)

    indep = [r for r in dev_rows if r[1] == "independent"]
    indep_matches = [r for r in match_rows if r[1] == "independent"]
    tiers = Counter(r[6] for r in indep)
    urgency = Counter(r[18] for r in indep_matches)
    checks = Counter(r[10] for r in indep_matches)
    lines = [
        f"Snapshot: {snapshot}",
        f"  built {lookup.meta.get('built_utc', 'unknown')}, {len(lookup.cves)} CVE records",
        f"  {snapshot_check(snapshot)}",
        f"Independent set: {len(indep)} devices",
        "  identity tier: " + ", ".join(f"{t} {tiers.get(t, 0)}" for t in ("A", "A-", "B", "C")),
        f"  devices with at least one match: {sum(1 for r in indep if r[8])}",
        f"Matches (tiers A and A-): {len(indep_matches)}",
        "  version check: " + ", ".join(f"{k} {v}" for k, v in sorted(checks.items())),
        "  urgency: " + ", ".join(f"{t} {urgency.get(t, 0)}" for t in TIERS),
        "  KEV-listed: " + str(sum(1 for r in indep_matches if r[15] == "Y")),
    ]
    for r in indep:
        if r[6] in ("A", "A-"):
            lines.append(f"  {r[0]} {r[2]} {r[4]} {r[5]}: {r[8]} matches")
    text = "\n".join(lines)
    (results / "correlation_summary.txt").write_text(text + "\n", encoding="utf-8")
    print(text)
    print(
        f"\nWritten: correlation_devices.csv, correlation_matches.csv, correlation_summary.txt in {results}"
    )


def summary(checked: Path, reference: Path | None) -> None:
    rows = [r for r in csv.DictReader(open(checked, encoding="utf-8-sig"))]
    rows = [r for r in rows if r.get("set", "independent") == "independent"]
    judged = [r for r in rows if (r.get("applies") or "").strip().upper() in ("Y", "N")]
    yes = [r for r in judged if r["applies"].strip().upper() == "Y"]
    print(f"Matches: {len(rows)}; checked: {len(judged)}")
    print(f"Correlation precision: {fmt(len(yes), len(judged))}")
    if reference:
        ref = {
            (r["ip"].strip(), r["cve_id"].strip().upper())
            for r in csv.DictReader(open(reference, encoding="utf-8-sig"))
        }
        found = {(r["ip"].strip(), r["cve_id"].strip().upper()) for r in yes}
        print(f"Correlation recall: {fmt(len(ref & found), len(ref))}")
        missed = sorted(ref - found)
        if missed:
            print("  missed: " + ", ".join(f"{ip} {cve}" for ip, cve in missed))
    tiered = [r for r in judged if (r.get("tier_manual") or "").strip()]
    if tiered:
        agree = sum(1 for r in tiered if r["tier_manual"].strip() == r["urgency_tier"])
        print(f"Tier agreement: {fmt(agree, len(tiered))}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", help="engine results folder")
    ap.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT))
    ap.add_argument("--summary", help="correlation_matches CSV with the manual columns filled")
    ap.add_argument("--reference", help="reference_vulns.csv (ip, cve_id)")
    args = ap.parse_args()
    if args.summary:
        summary(Path(args.summary), Path(args.reference) if args.reference else None)
    elif args.results:
        correlate(Path(args.results), Path(args.snapshot))
    else:
        ap.error("give --results or --summary")


if __name__ == "__main__":
    main()
