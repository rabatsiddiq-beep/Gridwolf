"""
appendix_d_check.py - run the Appendix D reproducibility procedure once more, end to end.

Steps (numbers as in Appendix D):
  2  test suite passes (skip with --skip-tests)
  4  every capture's SHA-256 matches Appendix B
  5  the committed vulnerability snapshot matches its recorded hash
  6  run_engine.py on all twelve captures   -> docs/thesis/results/appd-check
  8  evaluate.py on the new run
  9  correlation summary (precision, recall, tier agreement) from the verified matches
  11 robustness test (35 cases expected: 33 processed, 2 rejected, 0 crashed)
  12 repro_compare.py: new run against docs/thesis/results/final
and confirms that the engine code is unchanged since tag v-eval-final.

Read-only for everything already committed: all output goes to results/appd-check.

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/appendix_d_check.py --pcaps "C:\\...\\ICS-Security-Tools\\pcaps"
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "docs" / "thesis" / "scripts"
RES = REPO / "docs" / "thesis" / "results"
OUT = RES / "appd-check"
TAG, TAG_COMMIT = "v-eval-final", "ef418f49d1bf3e9f95e5a74afa162db2c429f315"
SNAPSHOT = REPO / "backend" / "app" / "vulndata" / "vuln_snapshot.json.gz"
SNAPSHOT_SHA256 = "68441bacb34e6da4cf1319928bfa210c114ef81d4f90456fe9590bac81298c24"
DATASET = {  # Appendix B (full hashes, as in docs/thesis/datasets.csv)
    "Combined/Plant1.pcap": "fc91932509a2a777dee0004cb686e92180aae2ad34d8eb3a447573e46091d41d",
    "ModbusTCP/ModbusTCP.pcap": "ae5e7b3101bd2f49390cfd77376ed176389aba9360307dd424dab51b339c5593",
    "ModbusTCP/modbus_test_data_part1.pcap": "94942b3d014810710f50836c95d3faf6df6e6370a6560bae541397c1df50213d",
    "s7/tia_s300_goOnline.pcapng": "e6d2359ffbbaf85efc56d85e060059c2cdb902bc19dfeb71f38298e4db8eb152",
    "s7/s7comm_reading_plc_status.pcap": "e71f81b471bd67da2fd6e40dc69a7179574ba66771c6150cd7bfe232cc07b8a9",
    "s7/wincc_s400_production.pcapng": "d0bae738862ee3157c73b2ca90230a3d0c8e21402923155296f9b86804a2f0ae",
    "EthernetIP/EthernetIP-CIP.pcap": "c50b510b3242f94c8aed9a4b6723962f182d04feca8a8dac09a96a135649461d",
    "CIP/cip_unclean.pcap": "3ba9452e4e65bb8843fdd3d9c7e2d6261824380b066ce994c71cb550966eec5c",
    "IEC60870-5-104/090813_diverse.pcap": "07b9a0879dc83e420c4cf83b37fb5830d1d8fb5f6ac6edc435896f70b0fc6bc7",
    "BACnet/bacnet_test.pcap": "973724800eef38e1131368d4ebce0eafc6593ccb4763916b8ee69b3b1328d8ff",
    "dnp3/full_exchange.pcap": "7373cc6e22c2a1ccd55a2a603436e93ad93e712b633e285b6d79796cceccd387",
    "profinet/PROFINET-RT-DCP/PROFINET-RT.pcap": "55ceb6e5c1ca1490c24d51d23084a554cecb95bdd9e9ae82e04b97c237798bbb",
}
results: list[tuple[str, str]] = []


def report(status: str, msg: str) -> None:
    results.append((status, msg))
    print(f"[{status:4s}] {msg}", flush=True)


def run(args: list[str], cwd: Path = REPO) -> tuple[int, str]:
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def py(script: str, *args: str) -> tuple[int, str]:
    return run([sys.executable, str(SCRIPTS / script), *args])


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcaps", required=True, help="ITI pcaps folder")
    ap.add_argument("--skip-tests", action="store_true")
    args = ap.parse_args()
    pcaps = Path(args.pcaps)
    OUT.mkdir(parents=True, exist_ok=True)

    print("Repository")
    code, tag = run(["git", "rev-parse", f"{TAG}^{{commit}}"])
    report("PASS" if tag == TAG_COMMIT else "FAIL", f"{TAG} -> {tag[:7] or 'missing'}")
    code, _ = run(["git", "diff", "--quiet", TAG, "HEAD", "--", "backend/app"])
    report("PASS" if code == 0 else "FAIL", "engine code unchanged since v-eval-final")

    print("\nStep 2: test suite")
    if args.skip_tests:
        report("WARN", "skipped (--skip-tests)")
    else:
        code, out = run([sys.executable, "-m", "pytest", "-q"], cwd=REPO / "backend")
        report(
            "PASS" if code == 0 else "FAIL",
            out.splitlines()[-1] if out else "no output",
        )

    print("\nStep 4: dataset hashes (Appendix B)")
    bad = []
    for rel, expected in DATASET.items():
        f = pcaps / rel
        if not f.exists():
            bad.append(f"{rel} missing")
        elif sha256(f) != expected:
            bad.append(f"{rel} differs")
    report(
        "FAIL" if bad else "PASS",
        "; ".join(bad) if bad else "all 12 captures match Appendix B",
    )

    print("\nStep 5: vulnerability snapshot")
    if SNAPSHOT.exists():
        report(
            "PASS" if sha256(SNAPSHOT) == SNAPSHOT_SHA256 else "FAIL",
            "snapshot hash 68441bac...",
        )
    else:
        report("FAIL", f"snapshot not found: {SNAPSHOT}")

    print("\nSteps 6 and 8: engine run and metrics -> results/appd-check")
    code, out = py("run_engine.py", "--pcaps", str(pcaps), "--out", str(OUT))
    report(
        "PASS" if code == 0 else "FAIL",
        f"run_engine.py ({len(list(OUT.glob('*.json')))} result files)",
    )
    code, out = py("evaluate.py", "--results", str(OUT))
    report(
        "PASS" if code == 0 and (OUT / "metrics.csv").exists() else "FAIL",
        "evaluate.py",
    )

    print("\nStep 9: correlation summary from the verified matches")
    checked = RES / "final" / "correlation_matches_checked.csv"
    ref = RES / "final" / "reference_vulns.csv"
    code, out = py(
        "evaluate_correlation.py", "--summary", str(checked), "--reference", str(ref)
    )
    lines = [
        ln
        for ln in out.splitlines()
        if ln.startswith(("Correlation precision", "Correlation recall", "Tier"))
    ]
    report(
        "PASS" if code == 0 and len(lines) >= 2 else "FAIL",
        " | ".join(lines) or out[-200:],
    )

    print("\nStep 11: robustness (a few minutes)")
    code, out = py("robustness.py", "--pcaps", str(pcaps), "--out", str(OUT))
    rob = OUT / "robustness.csv"
    if code == 0 and rob.exists():
        rows = list(csv.DictReader(open(rob, encoding="utf-8")))
        n = {
            k: sum(1 for r in rows if r["outcome"] == k)
            for k in ("processed", "rejected", "crash")
        }
        ok = len(rows) == 35 and n == {"processed": 33, "rejected": 2, "crash": 0}
        report("PASS" if ok else "FAIL", f"{len(rows)} cases: {n['processed']} processed, "
               f"{n['rejected']} rejected, {n['crash']} crashed")  # fmt: skip
    else:
        report("FAIL", out[-200:])

    print("\nStep 12: compare with the published run")
    code, out = py("repro_compare.py", "--a", str(RES / "final"), "--b", str(OUT))
    last = out.splitlines()[-2:] if out else ["no output"]
    report(
        "PASS" if "REPRODUCIBLE" == last[-1].strip() else "FAIL",
        " ".join(x.strip() for x in last),
    )

    fails = sum(1 for s, _ in results if s == "FAIL")
    warns = sum(1 for s, _ in results if s == "WARN")
    print(f"\n{'APPENDIX D REPRODUCED' if not fails else f'{fails} FAIL'}"
          + (f", {warns} WARN" if warns else "") + f"  (outputs in {OUT})")  # fmt: skip


if __name__ == "__main__":
    main()
