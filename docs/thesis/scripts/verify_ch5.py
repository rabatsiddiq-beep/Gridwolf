"""
verify_ch5.py - check the numbers in Chapter 5 and Appendix I against the results files.

Run it after every rewrite of Chapter 5, so that rewording never changes a number.

  1. Forward check: every headline figure computed from the results files (metrics,
     correlation check, miss analysis, robustness, reproducibility) must appear in the
     chapter or appendix, in any of its usual spellings ("64/64" or "64 of 64").
  2. Reverse check: every confidence interval written in the chapter or appendix must be
     either an interval from the results files or the Wilson interval of a k/n written
     in the text. A typo in an interval is reported.
  3. Placeholders: any [bracketed] text left in Chapter 5 or Appendix I is listed.
  4. Word count of Chapters 1-7 (prose plus tables, a conservative reading of the rules).

Tracked changes are read as accepted (deleted text is ignored). Read-only; standard library only.

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/verify_ch5.py --docx "C:\\path\\to\\CT7004_..._v5_Ch5_tracked.docx"
"""

from __future__ import annotations

import argparse
import csv
import re
import zipfile
from collections import Counter
from math import sqrt
from pathlib import Path

import xml.etree.ElementTree as etree

REPO = Path(__file__).resolve().parents[3]
RES = REPO / "docs" / "thesis" / "results"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}
LIMIT = 12000
GUIDE = (
    "GUIDANCE",
    "RESEARCH DATA TO INSERT",
    "FIGURE",
    "INSERT:",
    "INTERPRETATION TO WRITE",
    "TO COMPLETE",
)

results: list[tuple[str, str]] = []


def report(status: str, msg: str) -> None:
    results.append((status, msg))
    print(f"[{status:4s}] {msg}")


def wilson(k: int, n: int, z: float = 1.96) -> str:
    if n == 0:
        return ""
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{max(0.0, c - h):.3f}-{min(1.0, c + h):.3f}"


def norm(s: str) -> str:
    return s.replace("\u2013", "-").replace("\u2014", "-").replace("\u00a0", " ")


def ptext(p) -> str:
    return "".join(t.text or "" for t in p.iter(f"{{{W}}}t"))


def load_doc(path: Path):
    """Return a list of (chapter, kind, text) blocks, tracked changes accepted."""
    with zipfile.ZipFile(path) as z:
        root = etree.fromstring(z.read("word/document.xml"))
    blocks, chap = [], ""
    for el in root.find("w:body", NS):
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "p":
            st = el.find("w:pPr/w:pStyle", NS)
            style = st.get(f"{{{W}}}val") if st is not None else ""
            t = ptext(el)
            if style == "Heading1":
                chap = t.strip()
            elif style == "Heading2" and t.startswith("Appendix "):
                chap = t.strip()
            blocks.append((chap, "p", t))
        elif tag == "tbl":
            t = "\n".join(ptext(p) for p in el.iter(f"{{{W}}}p"))
            kind = "guide" if t.strip().startswith(GUIDE) else "tbl"
            blocks.append((chap, kind, t))
    return blocks


def rows(path: Path) -> list[dict]:
    return list(csv.DictReader(open(path, encoding="utf-8-sig")))


def frac(s: str) -> tuple[int, int]:
    k, n = s.split("/")
    return int(k), int(n)


def expected_claims() -> tuple[list[tuple[str, list[list[str]]]], set[str]]:
    """(claim name, groups of alternative spellings) and the set of valid intervals."""
    claims, cis = [], set()

    def kn(k, n):
        return [f"{k}/{n}", f"{k} / {n}", f"{k} of {n}", f"{k} of the {n}"]

    m = rows(RES / "final" / "metrics.csv")
    for r in m:
        for col in (
            "precision_ci",
            "recall_ci",
            "recall_incl_l2_ci",
            "role_ci",
            "class_ci",
        ):
            if r.get(col) and r[col] != "-":
                cis.add(r[col])
    allr = next(r for r in m if r["capture"].startswith("ALL"))
    tp, gt = int(allr["TP"]), int(allr["gt_devices"])
    claims.append(("discovery precision/recall", [kn(tp, gt), [allr["precision_ci"]]]))
    claims.append(
        (
            "recall including Layer 2",
            [[allr["recall_incl_l2"]], [allr["recall_incl_l2_ci"]]],
        )
    )
    k, n = frac(allr["role_correct"])
    claims.append(("role accuracy", [kn(k, n), [allr["role_ci"]]]))
    k, n = frac(allr["class_correct"])
    claims.append(
        ("class accuracy", [kn(k, n), [allr["class_accuracy"]], [allr["class_ci"]]])
    )
    k, n = frac(allr["product_correct"])
    claims.append(("product identity", [kn(k, n), [wilson(k, n)]]))
    cis.add(wilson(k, n))
    k, n = frac(allr["vendor_correct"])
    claims.append(("vendor coverage", [kn(k, n), [wilson(k, n)]]))
    cis.add(wilson(k, n))

    mp = RES / "final" / "metrics_by_protocol.csv"
    if mp.exists():
        for r in rows(mp):
            for col in ("precision_ci", "recall_ci", "role_ci", "class_ci"):
                if r.get(col) and r[col] != "-":
                    cis.add(r[col])
                    if not r["protocol"].startswith(("PROFINET", "Overall")):
                        claims.append(
                            (f"Table I.1/I.2 {r['protocol']} {col}", [[r[col]]])
                        )

    cm = RES / "final" / "confusion_matrix.csv"
    if cm.exists():
        grid = rows(cm)
        labels = [c for c in grid[0] if c != "reference \\ assigned"]
        diag = sum(
            int(r[r["reference \\ assigned"]])
            for r in grid
            if r["reference \\ assigned"] in labels
        )
        total = sum(int(r[c]) for r in grid for c in labels)
        claims.append(("confusion matrix diagonal", [kn(diag, total)]))

    chk = rows(RES / "final" / "correlation_matches_checked.csv")
    judged = [r for r in chk if (r.get("applies") or "").strip().upper() in ("Y", "N")]
    yes = [r for r in judged if r["applies"].strip().upper() == "Y"]
    claims.append(
        (
            "correlation precision",
            [kn(len(yes), len(judged)), [wilson(len(yes), len(judged))]],
        )
    )
    cis.add(wilson(len(yes), len(judged)))
    ref = rows(RES / "final" / "reference_vulns.csv")
    found = {(r["ip"].strip(), r["cve_id"].strip().upper()) for r in yes}
    hit = sum(1 for r in ref if (r["ip"].strip(), r["cve_id"].strip().upper()) in found)
    claims.append(("correlation recall", [kn(hit, len(ref)), [wilson(hit, len(ref))]]))
    cis.add(wilson(hit, len(ref)))
    tiered = [r for r in yes if (r.get("tier_manual") or "").strip()]
    if tiered:
        agree = sum(1 for r in tiered if r["tier_manual"].strip() == r["urgency_tier"])
        claims.append(
            (
                "tier agreement (vendor basis)",
                [kn(agree, len(tiered)), [wilson(agree, len(tiered))]],
            )
        )
        cis.add(wilson(agree, len(tiered)))
        if "tier_nvd_basis" in tiered[0]:
            agree_n = sum(
                1 for r in tiered if r["tier_nvd_basis"].strip() == r["urgency_tier"]
            )
            claims.append(("tier agreement (NVD basis)", [kn(agree_n, len(tiered))]))
    epss = [float(r["epss"]) for r in chk if (r.get("epss") or "").strip()]
    if epss:
        claims.append(("highest EPSS", [[f"{max(epss):.3f}"]]))

    miss = RES / "final" / "missed_reference_cves.csv"
    if miss.exists():
        mr = rows(miss)
        c = Counter((r["reason"], r.get("detail", "")) for r in mr)
        claims.append(("missed reference CVEs", [[str(len(mr))]]))
        claims.append(
            ("misses: family name", [[str(c[("product_name", "family_name")])]])
        )
        claims.append(("misses: near name", [[str(c[("product_name", "near_name")])]]))
        nis = sum(v for (reason, _), v in c.items() if reason == "not_in_snapshot")
        claims.append(("misses: not in snapshot", [[str(nis)]]))

    rob = RES / "robustness" / "robustness.csv"
    if rob.exists():
        rr = rows(rob)
        oc = Counter(r["outcome"] for r in rr)
        claims.append(
            ("robustness cases", [[f"{len(rr)} inputs", f"{len(rr)} of {len(rr)}"]])
        )
        claims.append(
            (
                "robustness processed/rejected",
                [
                    [f"{oc['processed']} processed", f"{oc['processed']} captures"],
                    [f"{oc['rejected']} rejected"],
                ],
            )
        )

    rep = RES / "repro-wsl" / "repro_report.csv"
    if rep.exists():
        rp = rows(rep)
        same = sum(1 for r in rp if r["result"] == "MATCH")
        claims.append(("reproducibility", [kn(same, len(rp))]))
        for r in rp:
            if r["content_sha256_b"]:
                claims.append((f"hash {r['file']}", [[r["content_sha256_b"][:16]]]))
    return claims, cis


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docx", required=True)
    args = ap.parse_args()
    blocks = load_doc(Path(args.docx))

    scope = [
        t
        for ch, kind, t in blocks
        if (ch.startswith("Chapter 5") or ch.startswith("Appendix I:"))
        and kind != "guide"
    ]
    text = norm("\n".join(scope))
    print(f"Chapter 5 and Appendix I: {len(text.split())} words read\n")

    print("1. Forward check (results -> text)")
    claims, cis = expected_claims()
    for name, groups in claims:
        missing = [g for g in groups if not any(norm(alt) in text for alt in g)]
        if missing:
            report(
                "FAIL",
                f"{name}: not found in text: "
                + " / ".join(" or ".join(g) for g in missing),
            )
        else:
            report("PASS", name)

    print("\n2. Reverse check (intervals in text -> results)")
    for k, n in re.findall(r"\b(\d+)\s*(?:/|of)\s*(\d+)\b", text):
        if 0 < int(n) <= 500 and int(k) <= int(n):
            cis.add(wilson(int(k), int(n)))
    found = sorted(set(re.findall(r"\b([01]\.\d{3}-[01]\.\d{3})\b", text)))
    bad = [c for c in found if c not in cis]
    if bad:
        report(
            "FAIL",
            f"{len(bad)} interval(s) not traceable to the results: {', '.join(bad)}",
        )
    else:
        report("PASS", f"all {len(found)} distinct intervals traceable to the results")

    print("\n3. Placeholders")
    ph = sorted(set(re.findall(r"\[[^\]]{1,60}\]", text)))
    if ph:
        report("WARN", "placeholders left: " + ", ".join(ph))
    else:
        report("PASS", "no [bracketed] placeholders in Chapter 5 or Appendix I")

    print("\n4. Word count (Chapters 1-7, prose and tables, guidance boxes excluded)")
    counts: Counter = Counter()
    for ch, kind, t in blocks:
        if ch.startswith("Chapter") and kind != "guide":
            counts[ch.split(":")[0]] += len(t.split())
    for ch in sorted(counts, key=lambda c: int(c.split()[1])):
        print(f"       {ch}: {counts[ch]:,}")
    total = sum(counts.values())
    status = "PASS" if total <= LIMIT else "FAIL"
    report(
        status,
        f"total {total:,} of {LIMIT:,} words ({LIMIT - total:,} left for Chapters 6 and 7)",
    )

    fails = sum(1 for s, _ in results if s == "FAIL")
    warns = sum(1 for s, _ in results if s == "WARN")
    print(
        f"\n{'ALL CHECKS PASSED' if not fails and not warns else f'{fails} FAIL, {warns} WARN'}"
    )


if __name__ == "__main__":
    main()
