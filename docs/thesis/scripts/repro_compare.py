"""
repro_compare.py - is the evaluation reproducible on a second machine? (Section 4.6)

Compares two results folders produced by run_engine.py and evaluate.py, e.g. the
Windows run (docs/thesis/results/final) and a fresh clone of tag v-eval-final run under
WSL Ubuntu (docs/thesis/results/repro-wsl).

For each of the 12 capture JSON files:
  raw_sha256_a / _b   SHA-256 of the file as written. These usually differ, because
                      Python on Windows writes CRLF line endings and Linux writes LF.
  content_sha256_a/_b SHA-256 of the parsed content, with keys sorted and the
                      engine_commit field removed (it records the commit the run was
                      started from, which is not part of the result). Device order and
                      list order are kept as written, so any ordering difference counts.
  result              MATCH when the content hashes are equal, otherwise DIFFERENT with
                      the first differing field.

metrics.csv is compared cell by cell after normalising line endings.

Usage (repo root):
    python docs/thesis/scripts/repro_compare.py --a docs/thesis/results/final --b docs/thesis/results/repro-wsl
writes repro_report.csv into the --b folder.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

VOLATILE = {"engine_commit"}


def canonical(path: Path) -> tuple[dict, str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    commit = data.get("engine_commit", "")
    for k in VOLATILE:
        data.pop(k, None)
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return data, hashlib.sha256(blob.encode("utf-8")).hexdigest(), commit


def first_difference(a, b, where: str = "") -> str:
    if type(a) is not type(b):
        return f"{where or 'root'}: type {type(a).__name__} vs {type(b).__name__}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{where}.{k}: present in one run only"
            d = first_difference(a[k], b[k], f"{where}.{k}")
            if d:
                return d
        return ""
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{where}: {len(a)} vs {len(b)} items"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{where}[{i}]")
            if d:
                return d
        return ""
    return "" if a == b else f"{where}: {a!r} vs {b!r}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--a", required=True, help="reference results folder (e.g. Windows run)"
    )
    ap.add_argument("--b", required=True, help="re-run results folder (e.g. WSL run)")
    args = ap.parse_args()
    a_dir, b_dir = Path(args.a), Path(args.b)

    rows, ok = [], True
    names = sorted(
        p.name
        for p in a_dir.glob("*.json")
        if p.name.endswith((".pcap.json", ".pcapng.json"))
    )
    if len(names) != 12:
        print(f"warning: {len(names)} capture JSON files in {a_dir}, expected 12")
    for name in names:
        fa, fb = a_dir / name, b_dir / name
        if not fb.exists():
            rows.append([name, "", "", "", "", "", "", "MISSING in --b"])
            ok = False
            continue
        da, ha, ca = canonical(fa)
        db, hb, cb = canonical(fb)
        same = ha == hb
        ok &= same
        rows.append(
            [
                name,
                hashlib.sha256(fa.read_bytes()).hexdigest(),
                hashlib.sha256(fb.read_bytes()).hexdigest(),
                ha,
                hb,
                ca,
                cb,
                "MATCH" if same else "DIFFERENT: " + first_difference(da, db),
            ]
        )

    ma, mb = a_dir / "metrics.csv", b_dir / "metrics.csv"
    if ma.exists() and mb.exists():
        ta = ma.read_text(encoding="utf-8").replace("\r\n", "\n").strip().splitlines()
        tb = mb.read_text(encoding="utf-8").replace("\r\n", "\n").strip().splitlines()
        diff = [f"line {i + 1}" for i, (x, y) in enumerate(zip(ta, tb)) if x != y]
        if len(ta) != len(tb):
            diff.append(f"{len(ta)} vs {len(tb)} lines")
        res = "MATCH" if not diff else "DIFFERENT: " + ", ".join(diff[:5])
        ok &= not diff
        rows.append(["metrics.csv", "", "", "", "", "", "", res])
    else:
        rows.append(
            ["metrics.csv", "", "", "", "", "", "", "MISSING (run evaluate.py on both)"]
        )
        ok = False

    out = b_dir / "repro_report.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["file", "raw_sha256_a", "raw_sha256_b", "content_sha256_a", "content_sha256_b",
             "engine_commit_a", "engine_commit_b", "result"]
        )  # fmt: skip
        w.writerows(rows)

    for r in rows:
        print(f"{r[0]:38s} {r[7][:90]}")
    n_match = sum(1 for r in rows if r[7] == "MATCH")
    print(f"\n{n_match}/{len(rows)} identical in content -> {out}")
    print("REPRODUCIBLE" if ok else "NOT REPRODUCIBLE: see the DIFFERENT rows above")


if __name__ == "__main__":
    main()
