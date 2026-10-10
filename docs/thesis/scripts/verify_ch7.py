"""
verify_ch7.py - check Chapter 7 and the abstract, and sweep the whole draft for loose ends.

  1. Forward check: the headline figures used in the answers to the research questions
     and in the abstract must appear there, computed from the results files.
  2. Reverse check: every confidence interval in Chapter 7 and the abstract must come
     from the results.
  3. Table 7.1: every objective has a status.
  4. Abstract length (at most 300 words, a common limit; check the module guide).
  5. Whole-draft sweep: [bracketed] placeholders and guidance boxes left anywhere, by
     section, and the Chapters 1-7 word count.

Tracked changes are read as accepted. Read-only; standard library only.

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/verify_ch7.py --docx "C:\\path\\to\\CT7004_..._v8.docx"
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

ABSTRACT_LIMIT = 300
# Brackets that belong in the text (Harvard medium labels, pip extras)
LEGITIMATE = {"[Computer program]", "[Dataset]", "[dev]", "[thesis]", "[Online]"}
results: list[tuple[str, str]] = []


def report(status: str, msg: str) -> None:
    results.append((status, msg))
    print(f"[{status:4s}] {msg}")


def rows(path: Path) -> list[dict]:
    return list(csv.DictReader(open(path, encoding="utf-8-sig")))


def kn(k: int, n: int) -> list[str]:
    return [f"{k}/{n}", f"{k} of {n}", f"{k} of the {n}"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docx", required=True)
    args = ap.parse_args()
    blocks = load_doc(Path(args.docx))
    ch7 = norm(
        "\n".join(
            t for ch, k, t in blocks if ch.startswith("Chapter 7") and k != "guide"
        )
    )
    abstract = norm(
        "\n".join(
            t for ch, k, t in blocks if ch == "Abstract" and t.strip() != "Abstract"
        )
    )

    # ------------------------------------------------------------ 1. forward
    print("1. Forward check (results -> Chapter 7 and abstract)")
    m = next(
        r for r in rows(RES / "final" / "metrics.csv") if r["capture"].startswith("ALL")
    )
    tp, gt = int(m["TP"]), int(m["gt_devices"])
    rk, rn = (int(x) for x in m["role_correct"].split("/"))
    ck, cn = (int(x) for x in m["class_correct"].split("/"))
    pk, pn = (int(x) for x in m["product_correct"].split("/"))
    chk = rows(RES / "final" / "correlation_matches_checked.csv")
    judged = [r for r in chk if (r.get("applies") or "").strip().upper() in ("Y", "N")]
    yes = [r for r in judged if r["applies"].strip().upper() == "Y"]
    ref = rows(RES / "final" / "reference_vulns.csv")
    found = {(r["ip"].strip(), r["cve_id"].strip().upper()) for r in yes}
    hits = sum(
        1 for r in ref if (r["ip"].strip(), r["cve_id"].strip().upper()) in found
    )
    tiered = [r for r in yes if (r.get("tier_manual") or "").strip()]
    agree_v = sum(1 for r in tiered if r["tier_manual"].strip() == r["urgency_tier"])
    agree_n = sum(
        1
        for r in tiered
        if (r.get("tier_nvd_basis") or "").strip() == r["urgency_tier"]
    )
    words = {3: "three", 6: "six"}
    claims = {
        "Chapter 7": [
            ("devices discovered", [f"all {tp}", *kn(tp, gt)]),
            ("discovery precision and recall", [f"{float(m['precision']):.3f}"]),
            ("discovery interval", [m["precision_ci"]]),
            ("roles", [f"all {rn}", *kn(rk, rn)]),
            ("classes", kn(ck, cn)),
            ("class accuracy", [m["class_accuracy"]]),
            ("recall including Layer 2", [m["recall_incl_l2"]]),
            ("product identity", [f"all {words.get(pn, pn)}", *kn(pk, pn)]),
            ("correlation precision", [f"{len(yes) / len(judged):.3f}"]),
            ("correlation recall", [*kn(hits, len(ref)), f"{hits / len(ref):.3f}"]),
            ("tier agreement, vendor basis", kn(agree_v, len(tiered))),
            ("tier agreement, NVD basis", kn(agree_n, len(tiered))),
        ],
        "Abstract": [
            ("devices discovered", [f"all {tp}", *kn(tp, gt)]),
            ("classes", kn(ck, cn)),
            ("correlation precision", [*kn(len(yes), len(judged)),
                                       f"{words.get(len(yes), len(yes))} of {words.get(len(judged), len(judged))}"]),
            ("correlation recall", kn(hits, len(ref))),
        ],
    }  # fmt: skip
    for where, items in claims.items():
        text = ch7 if where == "Chapter 7" else abstract
        for name, alts in items:
            if any(norm(a) in text for a in alts):
                report("PASS", f"{where}: {name}")
            else:
                report("FAIL", f"{where}: {name}: none of {alts} found")

    # ------------------------------------------------------------ 2. reverse
    print("\n2. Reverse check (intervals -> results)")
    cis = {
        m[c]
        for c in (
            "precision_ci",
            "recall_ci",
            "recall_incl_l2_ci",
            "role_ci",
            "class_ci",
        )
        if m.get(c)
    }
    both = ch7 + "\n" + abstract
    for k, n in re.findall(r"\b(\d+)\s*(?:/|of)\s*(\d+)\b", both):
        if 0 < int(n) <= 500 and int(k) <= int(n):
            cis.add(wilson(int(k), int(n)))
    found_ci = sorted(set(re.findall(r"\b([01]\.\d{3}-[01]\.\d{3})\b", both)))
    bad = [c for c in found_ci if c not in cis]
    report("FAIL" if bad else "PASS",
           f"intervals not traceable: {', '.join(bad)}" if bad else f"all {len(found_ci)} intervals traceable")  # fmt: skip

    # ------------------------------------------------------------ 3. Table 7.1
    print("\n3. Table 7.1 status")
    tbl = next(
        (
            t
            for ch, k, t in blocks
            if ch.startswith("Chapter 7") and k == "tbl" and "Objective" in t
        ),
        "",
    )
    lines = [ln for ln in tbl.split("\n") if ln.strip()]
    statuses = [
        lines[i + 2] if i + 2 < len(lines) else ""
        for i, ln in enumerate(lines)
        if re.match(r"O\d ", ln)
    ]
    missing = [s for s in statuses if not s.strip() or s.strip().startswith("[")]
    report("FAIL" if missing or not statuses else "PASS",
           f"{len(statuses)} objectives, {len(missing)} without a status")  # fmt: skip

    # ------------------------------------------------------------ 4. abstract length
    print("\n4. Abstract")
    n_abs = len(abstract.split())
    report(
        "PASS" if n_abs <= ABSTRACT_LIMIT else "WARN",
        f"abstract {n_abs} words (limit {ABSTRACT_LIMIT})",
    )

    # ------------------------------------------------------------ 5. sweep
    print("\n5. Whole-draft sweep")
    where: Counter = Counter()
    examples: dict[str, str] = {}
    for ch, kind, t in blocks:
        sec = ch or "front matter"
        if kind == "guide":
            where[f"{sec} (guidance box)"] += 1
            examples.setdefault(f"{sec} (guidance box)", t.strip()[:60])
        for ph in re.findall(r"\[[^\]]{1,80}\]", t):
            if re.fullmatch(r"\[\d+\]", ph) or ph in LEGITIMATE:
                continue
            where[sec] += 1
            examples.setdefault(sec, ph)
    if where:
        for sec, n in where.most_common():
            report("WARN", f"{sec}: {n} item(s), e.g. {examples[sec]}")
    else:
        report("PASS", "no placeholders or guidance boxes left")
    counts: Counter = Counter()
    for ch, kind, t in blocks:
        if ch.startswith("Chapter") and kind != "guide":
            counts[ch.split(":")[0]] += len(t.split())
    total = sum(counts.values())
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
