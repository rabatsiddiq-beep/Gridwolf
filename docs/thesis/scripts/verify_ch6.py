"""
verify_ch6.py - check Chapter 6 against the results files and the reference list.

Run it after drafting and after every rewrite of Chapter 6.

  1. Forward check: the figures Chapter 6 discusses (iteration results, correlation
     precision and recall, the upper bound for family-level matching, the CVSS scores
     compared, Layer-2 recall) must appear in the chapter.
  2. Reverse check: every confidence interval in Chapter 6 (including Table 6.1) must
     come from a metrics file or be the Wilson interval of a k/n written in the text.
  3. Citations: every author-year citation in Chapters 1-7 must have an entry in the
     reference list, and every reference should be cited at least once.
  4. Placeholders and guidance boxes left in Chapter 6, and the word count.

Tracked changes are read as accepted. Read-only; standard library only.

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/verify_ch6.py --docx "C:\\path\\to\\CT7004_..._v6_Ch6_tracked.docx"
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_ch5 import LIMIT, RES, load_doc, norm, wilson  # noqa: E402

ITERATIONS = {
    "Iteration 0": "baseline",
    "Iteration 1": "fix-roles",
    "Iteration 2": "final",
}
results: list[tuple[str, str]] = []


def report(status: str, msg: str) -> None:
    results.append((status, msg))
    print(f"[{status:4s}] {msg}")


def rows(path: Path) -> list[dict]:
    return list(csv.DictReader(open(path, encoding="utf-8-sig")))


def metric_intervals(m: dict) -> set[str]:
    """Wilson intervals for every proportion in one metrics.csv 'ALL' row."""
    out = set()
    tp, gt, pred = int(m["TP"]), int(m["gt_devices"]), int(m["predicted"])
    l2 = int(m.get("l2_only") or 0)
    for k, n in ((tp, pred), (tp, gt), (tp, gt + l2)):
        out.add(wilson(k, n))
    for col in ("role_correct", "class_correct", "product_correct"):
        if m.get(col) and "/" in m[col]:
            k, n = (int(x) for x in m[col].split("/"))
            out.add(wilson(k, n))
    for col in (
        "precision_ci",
        "recall_ci",
        "recall_incl_l2_ci",
        "role_ci",
        "class_ci",
    ):
        if m.get(col) and m[col] != "-":
            out.add(m[col])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docx", required=True)
    args = ap.parse_args()
    blocks = load_doc(Path(args.docx))
    ch6_blocks = [(k, t) for ch, k, t in blocks if ch.startswith("Chapter 6")]
    ch6 = norm("\n".join(t for k, t in ch6_blocks if k != "guide"))
    print(f"Chapter 6: {len(ch6.split())} words read\n")

    # ------------------------------------------------------------ 1. forward
    print("1. Forward check (results -> Chapter 6)")
    claims: list[tuple[str, list[str]]] = []
    cis: set[str] = set()
    for label, folder in ITERATIONS.items():
        f = RES / folder / "metrics.csv"
        if not f.exists():
            report("WARN", f"{label}: {f} not found, iteration figures not checked")
            continue
        m = next(r for r in rows(f) if r["capture"].startswith("ALL"))
        cis |= metric_intervals(m)
        claims.append((f"{label} class accuracy", [m["class_accuracy"]]))
        claims.append((f"{label} role accuracy", [m["role_accuracy"]]))
        if label == "Iteration 2":
            claims.append(("recall including Layer 2", [m["recall_incl_l2"]]))
    chk = rows(RES / "final" / "correlation_matches_checked.csv")
    judged = [r for r in chk if (r.get("applies") or "").strip().upper() in ("Y", "N")]
    yes = [r for r in judged if r["applies"].strip().upper() == "Y"]
    ref = rows(RES / "final" / "reference_vulns.csv")
    found = {(r["ip"].strip(), r["cve_id"].strip().upper()) for r in yes}
    hits = sum(
        1 for r in ref if (r["ip"].strip(), r["cve_id"].strip().upper()) in found
    )
    claims.append(("correlation precision", [f"{len(yes) / len(judged):.3f}"]))
    claims.append(("correlation recall", [f"{hits / len(ref):.3f}"]))
    cis |= {wilson(len(yes), len(judged)), wilson(hits, len(ref))}
    miss = RES / "final" / "missed_reference_cves.csv"
    if miss.exists():
        names = sum(1 for r in rows(miss) if r["reason"] == "product_name")
        claims.append(
            (
                "family-level upper bound",
                [f"{hits + names} of {len(ref)}", f"{hits + names}/{len(ref)}"],
            )
        )
        claims.append(("product-name misses", [str(names)]))
    per_device = Counter(r["ip"].strip() for r in ref)
    top_ip, top_n = per_device.most_common(1)[0]
    claims.append((f"reference CVEs for {top_ip}", [f"{top_n} applicable"]))
    for r in yes:
        for col in ("cvss_vendor", "cvss_nvd"):
            if r.get(col):
                claims.append((f"{r['cve_id']} {col}", [str(r[col])]))
    for name, alts in claims:
        if any(norm(a) in ch6 for a in alts):
            report("PASS", name)
        else:
            report("FAIL", f"{name}: none of {alts} found in Chapter 6")

    # ------------------------------------------------------------ 2. reverse
    print("\n2. Reverse check (intervals in Chapter 6 -> results)")
    for k, n in re.findall(r"\b(\d+)\s*(?:/|of)\s*(\d+)\b", ch6):
        if 0 < int(n) <= 500 and int(k) <= int(n):
            cis.add(wilson(int(k), int(n)))
    found_ci = sorted(set(re.findall(r"\b([01]\.\d{3}-[01]\.\d{3})\b", ch6)))
    bad = [c for c in found_ci if c not in cis]
    if bad:
        report("FAIL", f"intervals not traceable to the results: {', '.join(bad)}")
    else:
        report(
            "PASS", f"all {len(found_ci)} distinct intervals traceable to the results"
        )

    # ------------------------------------------------------------ 3. citations
    print("\n3. Citations (Chapters 1-7) against the reference list")
    refs = []
    for ch, kind, t in blocks:
        if (
            ch == "References"
            and kind == "p"
            and t.strip()
            and t.strip() != "References"
        ):
            m = re.match(r"(.+?)\s\((\d{4}[a-z]?)\)", t.strip())
            if m:
                head = re.split(r",|\s\(", m.group(1))[0].strip()
                refs.append((head, m.group(2), t.strip()))
    body = norm(
        "\n".join(t for ch, k, t in blocks if ch.startswith("Chapter") and k != "guide")
    )
    cited: Counter = Counter()
    unknown = []
    for m in re.finditer(r"(\(|, )((?:19|20)\d{2}[a-z]?)\b", body):
        year = m.group(2)
        before = body[max(0, m.start() - 70) : m.start() + 1]
        words = set(re.findall(r"[A-Z][A-Za-z\-’']+", before))
        hit = [
            (h, y)
            for h, y, _ in refs
            if y == year and re.split(r"[\s/]", h)[-1] in words
        ]
        if hit:
            cited.update(hit)
        elif words:
            unknown.append(f"...{before[-45:].strip()}{year}")
    if unknown:
        report(
            "WARN",
            f"{len(unknown)} citation(s) with no matching reference: "
            + "; ".join(sorted(set(unknown))[:8]),
        )
    else:
        report("PASS", "every author-year citation found in the reference list")
    uncited = [f"{h} ({y})" for h, y, _ in refs if (h, y) not in cited]
    if uncited:
        report(
            "INFO",
            f"{len(uncited)} reference(s) not matched to a citation in Chapters 1-7 (check by hand): "
            + ", ".join(uncited[:12]),
        )

    # ------------------------------------------------------------ 4. placeholders, boxes, words
    print("\n4. Placeholders, guidance boxes and word count")
    ph = sorted(set(re.findall(r"\[[^\]]{1,80}\]", ch6)))
    report(
        "WARN" if ph else "PASS",
        ("placeholders left: " + ", ".join(ph))
        if ph
        else "no [bracketed] placeholders",
    )
    boxes = [t.split("(")[0].strip() for k, t in ch6_blocks if k == "guide"]
    report(
        "WARN" if boxes else "PASS",
        ("guidance boxes still to write: " + "; ".join(boxes))
        if boxes
        else "no guidance boxes left",
    )
    counts: Counter = Counter()
    for ch, kind, t in blocks:
        if ch.startswith("Chapter") and kind != "guide":
            counts[ch.split(":")[0]] += len(t.split())
    total = sum(counts.values())
    print(
        "       "
        + ", ".join(
            f"{c.split()[1]}: {counts[c]:,}"
            for c in sorted(counts, key=lambda c: int(c.split()[1]))
        )
    )
    report(
        "PASS" if total <= LIMIT else "FAIL",
        f"Chapters 1-7: {total:,} of {LIMIT:,} words ({LIMIT - total:,} left)",
    )

    fails = sum(1 for s, _ in results if s == "FAIL")
    warns = sum(1 for s, _ in results if s == "WARN")
    print(
        f"\n{'ALL CHECKS PASSED' if not fails and not warns else f'{fails} FAIL, {warns} WARN'}"
    )


if __name__ == "__main__":
    main()
