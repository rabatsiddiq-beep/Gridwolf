"""
make_figures.py - figures for Chapters 5 and 6, drawn from the evaluation outputs.

  Figure 5.1  confusion matrix: reference device class (codebook R3) against the class
              the workflow assigned, for the independent set (single-host simulator
              excluded). Also written as confusion_matrix.csv.
  Figure 6.1  (optional, with --iterations) role and class accuracy with 95% Wilson
              intervals for each design iteration, read from each run's metrics.csv.

Usage (repo root, backend virtual environment active; needs matplotlib):
    python docs/thesis/scripts/make_figures.py --results docs/thesis/results/final
    python docs/thesis/scripts/make_figures.py --results docs/thesis/results/final ^
        --iterations "Iteration 0=docs/thesis/results/baseline" ^
                     "Iteration 1=docs/thesis/results/fix-roles" ^
                     "Iteration 2=docs/thesis/results/final"
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import CLASS_MAP, GT, SUBSETS, wilson  # noqa: E402

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:  # pragma: no cover - reported to the user
    plt = None

INK, INK_2, GRID, MUTED, ACCENT = "#0b0b0b", "#52514e", "#e4e3df", "#9a9a96", "#2a78d6"
CLASS_ORDER = [
    "PLC",
    "RTU",
    "BACnet controller",
    "OT device (vendor protocol)",
    "HMI/SCADA",
    "Engineering workstation",
    "Historian/DB server",
    "IT/Other",
]


def confusion(results: Path) -> Counter:
    gt = list(csv.DictReader(open(GT, encoding="utf-8-sig")))
    pairs: Counter = Counter()
    for cap in sorted({r["capture"] for r in gt} - SUBSETS):
        f = results / f"{cap}.json"
        if not f.exists():
            continue
        pred = {d["ip"]: d for d in json.loads(f.read_text(encoding="utf-8"))["devices"]}
        for r in gt:
            if r["capture"] != cap or r["is_device"] != "Y":
                continue
            if r["device_class"] == "Simulator (single host)":
                continue
            d = pred.get(r["ip"])
            assigned = (
                CLASS_MAP.get(d.get("device_type") or "UNKNOWN", "IT/Other") if d else "missed"
            )
            pairs[(r["device_class"], assigned)] += 1
    return pairs


def write_confusion(results: Path, pairs: Counter) -> None:
    labels = [c for c in CLASS_ORDER if any(c in p for p in pairs)]
    labels += sorted({c for p in pairs for c in p} - set(labels))
    with open(results / "confusion_matrix.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["reference \\ assigned"] + labels)
        for ref in labels:
            w.writerow([ref] + [pairs.get((ref, a), 0) for a in labels])
    if plt is None:
        print("matplotlib not installed: wrote confusion_matrix.csv only (pip install matplotlib)")
        return

    n = len(labels)
    grid = [[pairs.get((ref, a), 0) for a in labels] for ref in labels]
    total = sum(map(sum, grid))
    correct = sum(grid[i][i] for i in range(n))
    fig, ax = plt.subplots(figsize=(7.6, 6.2), dpi=200)
    ax.imshow(grid, cmap="Blues", vmin=0, vmax=max(max(r) for r in grid) * 1.15)
    for i in range(n):
        for j in range(n):
            v = grid[i][j]
            if v:
                dark = v > max(max(r) for r in grid) * 0.55
                ax.text(j, i, str(v), ha="center", va="center", fontsize=10,
                        color="white" if dark else INK,
                        fontweight="bold" if i == j else "normal")  # fmt: skip
    ax.set_xticks(range(n), labels, rotation=35, ha="right", fontsize=8.5, color=INK_2)
    ax.set_yticks(range(n), labels, fontsize=8.5, color=INK_2)
    ax.set_xlabel("Class assigned by the workflow", fontsize=9, color=INK_2)
    ax.set_ylabel("Reference class (codebook)", fontsize=9, color=INK_2)
    ax.set_title(
        f"{correct} of {total} devices classified correctly; errors sit off the diagonal",
        loc="left", fontsize=10.5, color=INK,
    )  # fmt: skip
    for s in ax.spines.values():
        s.set_color(GRID)
    ax.tick_params(length=0)
    fig.tight_layout()
    out = results / "figure_5_1_confusion.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"Figure 5.1: {out} ({correct}/{total} on the diagonal)")


def iteration_figure(results: Path, specs: list[str]) -> None:
    runs = []
    for spec in specs:
        name, _, path = spec.partition("=")
        metrics = Path(path) / "metrics.csv"
        row = next(
            r
            for r in csv.DictReader(open(metrics, encoding="utf-8"))
            if r["capture"].startswith("ALL")
        )
        runs.append((name, row["role_correct"], row["class_correct"]))
    if plt is None:
        print("matplotlib not installed: Figure 6.1 skipped (pip install matplotlib)")
        return

    fig, axes = plt.subplots(1, 2, figsize=(8.0, 3.4), dpi=200, sharey=True)
    for ax, idx, label in ((axes[0], 1, "Role accuracy"), (axes[1], 2, "Class accuracy")):
        for x, run in enumerate(runs):
            k, n = (int(v) for v in run[idx].split("/"))
            lo, hi = wilson(k, n)
            colour = ACCENT if x == len(runs) - 1 else MUTED
            ax.plot([x, x], [lo, hi], color=colour, linewidth=2, solid_capstyle="round")
            ax.plot(x, k / n, "o", color=colour, markersize=8, markeredgecolor="white")
            ax.text(x + 0.12, k / n, f"{k}/{n}\n{k / n:.3f}", va="center", fontsize=8, color=INK)
        ax.set_xticks(range(len(runs)), [r[0] for r in runs], fontsize=8.5, color=INK_2)
        ax.set_xlim(-0.4, len(runs) - 0.3)
        ax.set_ylim(0, 1.05)
        ax.set_title(label, loc="left", fontsize=10, color=INK)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_color(GRID)
        ax.tick_params(length=0, labelsize=8, colors=INK_2)
    axes[0].set_ylabel("Proportion correct (95% Wilson interval)", fontsize=8.5, color=INK_2)
    first, last = (int(v) for v in runs[0][2].split("/")), (int(v) for v in runs[-1][2].split("/"))
    k0, n0 = first
    k1, n1 = last
    fig.suptitle(
        f"Class accuracy rose from {k0 / n0:.3f} to {k1 / n1:.3f} over {len(runs)} design iterations",
        x=0.01, ha="left", fontsize=11, color=INK,
    )  # fmt: skip
    fig.tight_layout()
    out = results / "figure_6_1_iterations.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"Figure 6.1: {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, help="results folder of the run to draw")
    ap.add_argument(
        "--iterations", nargs="*", default=[], help='"Name=results folder" per iteration'
    )
    args = ap.parse_args()
    results = Path(args.results)
    write_confusion(results, confusion(results))
    if args.iterations:
        iteration_figure(results, args.iterations)


if __name__ == "__main__":
    main()
