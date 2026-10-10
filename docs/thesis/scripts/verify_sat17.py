"""
verify_sat17.py - end-of-day check for Saturday 17 October (tiers, robustness, reproducibility).

Prints PASS / WARN / FAIL for each check and a final verdict. Read-only: changes nothing.

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/verify_sat17.py
"""

from __future__ import annotations

import csv
import hashlib
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RESULTS = REPO / "docs" / "thesis" / "results"
CHECKED = RESULTS / "final" / "correlation_matches_checked.csv"
ROBUST = RESULTS / "robustness" / "robustness.csv"
REPRO = RESULTS / "repro-wsl" / "repro_report.csv"
SNAPSHOT = REPO / "backend" / "app" / "vulndata" / "vuln_snapshot.json.gz"

TAG, TAG_COMMIT = "v-eval-final", "ef418f49d1bf3e9f95e5a74afa162db2c429f315"
SNAPSHOT_SHA256 = "68441bacb34e6da4cf1319928bfa210c114ef81d4f90456fe9590bac81298c24"
EXPECTED_TIERS = {  # (ip, cve) -> (workflow tier, tier_manual vendor basis, NVD basis)
    ("192.168.1.40", "CVE-2022-30694"): ("monitor", "monitor", "low_risk"),
    ("134.217.61.211", "CVE-2019-13940"): ("monitor", "monitor", "plan_patch"),
    ("134.217.61.211", "CVE-2022-30694"): ("monitor", "monitor", "low_risk"),
}
# Robustness run on 10 Oct 2026 (seed 2026): case -> (outcome, packets processed, devices)
_MUT = {
    "modbus_test_data_part1.pcap": (118, 4),
    "tia_s300_goOnline.pcapng": (448, 2),
    "cip_unclean.pcap": (2000, 2),
    "full_exchange.pcap": (22, 2),
    "090813_diverse.pcap": (173, 1),
    "bacnet_test.pcap": (26, 2),
}
EXPECTED_ROBUSTNESS = {
    "fuzz-72.pcap": ("processed", 36, 2),
    "fuzz-1011.pcap": ("processed", 6, 2),
    **{
        f"{cap} [{m}]": ("processed", pk, dv)
        for cap, (pk, dv) in _MUT.items()
        for m in ("flip", "truncate", "extend", "zero", "mixed")
    },
    "modbus_test_data_part1.pcap cut at 60%": ("processed", 76, 4),
    "random bytes": ("rejected", 0, 0),
    "empty file": ("rejected", 0, 0),
}

results: list[tuple[str, str, str]] = []


def report(status: str, check: str, detail: str = "") -> None:
    results.append((status, check, detail))
    print(f"[{status:4s}] {check}" + (f"  - {detail}" if detail else ""))


def git(*args: str) -> tuple[int, str]:
    p = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    return p.returncode, p.stdout.strip()


def check_git() -> None:
    _, tag = git("rev-parse", f"{TAG}^{{commit}}")
    if tag == TAG_COMMIT:
        report("PASS", f"tag {TAG} still points to {TAG_COMMIT[:7]}")
    else:
        report(
            "FAIL",
            f"tag {TAG} points to {tag[:7] or 'nothing'}, expected {TAG_COMMIT[:7]}",
        )
    code, _ = git("diff", "--quiet", TAG, "HEAD", "--", "backend/app")
    if code == 0:
        report("PASS", "engine code (backend/app) unchanged since v-eval-final")
    else:
        _, files = git("diff", "--name-only", TAG, "HEAD", "--", "backend/app")
        report(
            "FAIL", "engine code changed since v-eval-final", files.replace("\n", ", ")
        )
    if SNAPSHOT.exists():
        digest = hashlib.sha256(SNAPSHOT.read_bytes()).hexdigest()
        if digest == SNAPSHOT_SHA256:
            report("PASS", "vulnerability snapshot hash matches Appendix value")
        else:
            report("FAIL", "vulnerability snapshot hash differs", digest)
    else:
        report("WARN", "vulnerability snapshot not found", str(SNAPSHOT))


def check_tiers() -> None:
    if not CHECKED.exists():
        report("FAIL", "checked matches file missing", str(CHECKED))
        return
    rows = list(csv.DictReader(open(CHECKED, encoding="utf-8-sig")))
    if "tier_manual" not in rows[0] or "tier_nvd_basis" not in rows[0]:
        report("FAIL", "tier columns missing: run tier_check.py first")
        return
    yes = [r for r in rows if (r.get("applies") or "").strip().upper() == "Y"]
    filled = [r for r in yes if r["tier_manual"].strip()]
    if len(filled) == len(yes) == 3:
        report("PASS", "tier_manual filled for all 3 applicable matches")
    else:
        report(
            "FAIL",
            f"tier_manual filled for {len(filled)} of {len(yes)} applicable matches",
        )
    agree = sum(1 for r in filled if r["tier_manual"].strip() == r["urgency_tier"])
    agree_nvd = sum(
        1 for r in filled if r["tier_nvd_basis"].strip() == r["urgency_tier"]
    )
    report(
        "INFO",
        f"tier agreement: vendor basis {agree}/{len(filled)}, NVD basis {agree_nvd}/{len(filled)}",
    )
    bad = []
    for r in filled:
        exp = EXPECTED_TIERS.get((r["ip"].strip(), r["cve_id"].strip().upper()))
        got = (r["urgency_tier"], r["tier_manual"].strip(), r["tier_nvd_basis"].strip())
        if exp and got != exp:
            bad.append(f"{r['ip']} {r['cve_id']} {got} expected {exp}")
    if bad:
        report("WARN", "tiers differ from the expected values", "; ".join(bad))
    else:
        report(
            "PASS", "tiers match the expected values (3/3 vendor basis, 0/3 NVD basis)"
        )
    stray = [r for r in rows if r not in yes and (r.get("tier_manual") or "").strip()]
    if stray:
        report(
            "WARN",
            f"{len(stray)} non-applicable rows have tier_manual set (leave them empty)",
        )


def check_robustness() -> None:
    if not ROBUST.exists():
        report("FAIL", "robustness.csv missing", str(ROBUST))
        return
    rows = list(csv.DictReader(open(ROBUST, encoding="utf-8")))
    counts = {
        k: sum(1 for r in rows if r["outcome"] == k)
        for k in ("processed", "rejected", "crash")
    }
    summary = f"{len(rows)} cases: {counts['processed']} processed, {counts['rejected']} rejected, {counts['crash']} crashed"
    if len(rows) == 35 and counts == {"processed": 33, "rejected": 2, "crash": 0}:
        report("PASS", "robustness outcomes", summary)
    elif counts["crash"] == 0 and len(rows) >= 33:
        report(
            "WARN",
            "robustness outcomes differ from 35/33/2/0 but nothing crashed",
            summary,
        )
    else:
        report("FAIL", "robustness outcomes", summary)
    if len(rows) == 33:
        report(
            "WARN",
            "fuzzed captures missing: run git sparse-checkout add pcaps/bro/modbus",
        )
    diffs = []
    for r in rows:
        exp = EXPECTED_ROBUSTNESS.get(r["case"])
        got = (r["outcome"], int(r["packets_processed"]), int(r["devices"]))
        if exp is None:
            diffs.append(f"unexpected case {r['case']}")
        elif got != exp:
            diffs.append(f"{r['case']}: {got} vs {exp}")
    if diffs:
        report(
            "WARN",
            f"{len(diffs)} robustness rows differ from the reference run",
            "; ".join(diffs[:4]),
        )
    elif rows:
        report(
            "PASS",
            "every robustness row matches the reference run (outcome, packets, devices)",
        )
    errs = sum(int(r["packet_errors"]) for r in rows)
    report("INFO", f"malformed packets skipped by the per-packet guard: {errs}")


def check_repro() -> None:
    if not REPRO.exists():
        report(
            "FAIL",
            "repro_report.csv missing: run repro_compare.py after the WSL run",
            str(REPRO),
        )
        return
    rows = list(csv.DictReader(open(REPRO, encoding="utf-8")))
    match = [r for r in rows if r["result"] == "MATCH"]
    caps = [r for r in rows if r["file"] != "metrics.csv"]
    if len(rows) == 13 and len(match) == 13:
        report(
            "PASS",
            "reproducibility: 12 capture results and metrics.csv identical in content",
        )
    else:
        bad = [f"{r['file']}: {r['result']}" for r in rows if r["result"] != "MATCH"]
        report(
            "FAIL",
            f"reproducibility: {len(match)}/{len(rows)} identical",
            "; ".join(bad[:3]),
        )
    commits = {r["engine_commit_b"] for r in caps if r["engine_commit_b"]}
    if commits and commits <= {TAG_COMMIT[:7], TAG_COMMIT[:8], TAG_COMMIT[:9]}:
        report("PASS", f"WSL run was made from {TAG} ({', '.join(sorted(commits))})")
    elif commits:
        report(
            "WARN",
            f"WSL run engine_commit {', '.join(sorted(commits))}, expected {TAG_COMMIT[:7]}",
        )
    raw_same = sum(1 for r in caps if r["raw_sha256_a"] == r["raw_sha256_b"])
    report(
        "INFO",
        f"raw file hashes equal for {raw_same}/{len(caps)} (CRLF vs LF and engine_commit explain the rest)",
    )


def check_committed() -> None:
    _, dirty = git("status", "--porcelain", "--", "docs/thesis")
    if dirty:
        report(
            "WARN",
            "uncommitted changes under docs/thesis",
            dirty.replace("\n", " | ")[:200],
        )
    else:
        report("PASS", "docs/thesis fully committed")
    _, head = git("rev-parse", "HEAD")
    code, remote = git("rev-parse", "origin/thesisgrid")
    if code == 0 and head == remote:
        report("PASS", "HEAD pushed to origin/thesisgrid")
    else:
        report("WARN", "HEAD not yet pushed: run git push origin thesisgrid")


def main() -> None:
    print("Saturday 17 October - verification\n")
    for section, fn in (
        ("Repository", check_git),
        ("A. Urgency tiers", check_tiers),
        ("B. Robustness", check_robustness),
        ("C. Reproducibility", check_repro),
        ("D. Commit and push", check_committed),
    ):
        print(f"\n{section}")
        fn()
    fails = sum(1 for s, _, _ in results if s == "FAIL")
    warns = sum(1 for s, _, _ in results if s == "WARN")
    print(
        f"\n{'ALL CHECKS PASSED' if not fails and not warns else f'{fails} FAIL, {warns} WARN'}"
    )


if __name__ == "__main__":
    main()
