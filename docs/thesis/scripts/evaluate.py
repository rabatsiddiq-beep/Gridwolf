"""
evaluate.py - compare Gridwolf engine output with the verified ground truth.

Metrics (RQ1):
  * Discovery: precision, recall, F1 of observable devices (codebook R1)
  * Recall incl. Layer-2: recall when devices that send no IP packets
    (l2_devices.csv) are also counted as devices that should be found
  * Role: accuracy of server/client role for devices whose ground-truth role is
    server or client (codebook R2; 'both' and 'none-ICS' are not scored)
  * Class: accuracy of device class (codebook R3), after mapping Gridwolf device
    types to codebook classes (CLASS_MAP); single-host simulators are not scored
  * Identity (RQ1/RQ2): vendor, product and firmware compared with the codebook
    R4/R5 labels for devices whose ground truth has them; a product reported for a
    device whose ground truth has none is counted as a false identity

Aggregates use only the independent captures (codebook R8: the Plant1 subsets
ModbusTCP.pcap and EthernetIP-CIP.pcap are reported but not pooled).

Usage:
    python docs/thesis/scripts/evaluate.py --results docs/thesis/results/<label>
"""

import argparse
import csv
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GT = REPO / "docs/thesis/ground_truth/ground_truth_all.csv"
L2 = REPO / "docs/thesis/ground_truth/l2_devices.csv"
SUBSETS = {"ModbusTCP.pcap", "EthernetIP-CIP.pcap"}

SERVER_TYPES = {"PLC", "RTU", "SENSOR", "DCS", "RELAY", "METER", "OT_DEVICE"}
CLIENT_TYPES = {"HMI", "SCADA_SERVER", "ENGINEERING_WORKSTATION", "WORKSTATION"}


# Gridwolf device_type -> codebook R3 class
CLASS_MAP = {
    "PLC": "PLC",
    "RTU": "RTU",
    "SENSOR": "BACnet controller",
    "HMI": "HMI/SCADA",
    "SCADA_SERVER": "HMI/SCADA",
    "WORKSTATION": "HMI/SCADA",
    "ENGINEERING_WORKSTATION": "Engineering workstation",
    "HISTORIAN": "Historian/DB server",
    "OT_DEVICE": "OT device (vendor protocol)",
    "UNKNOWN": "IT/Other",
}


def l2_counts() -> dict:
    """Distinct devices per capture that send no IP packets (l2_devices.csv)."""
    counts: dict = {}
    if not L2.exists():
        return counts
    for r in csv.DictReader(open(L2, encoding="utf-8-sig")):
        if r["sends_ip_packets"] != "N":
            continue
        if r["notes"].startswith(("Port MAC", "Same physical")):  # second port of a switch
            continue
        counts[r["capture"]] = counts.get(r["capture"], 0) + 1
    return counts


def predicted_role(dev: dict) -> str:
    """Use the engine's explicit role if it reports one, else derive it from device_type."""
    if dev.get("role"):
        return dev["role"]
    t = dev.get("device_type") or "UNKNOWN"
    if t in SERVER_TYPES:
        return "server"
    if t in CLIENT_TYPES:
        return "client"
    return "none"


def _norm(text) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def vendor_matches(pred, truth: str) -> bool:
    """True if the first word of the predicted vendor appears in the ground-truth
    vendor label (e.g. 'Siemens AG' vs 'Siemens AG'; 'JCI' vs 'Johnson Controls (JCI, ...)')."""
    words = re.findall(r"[a-z0-9]+", (pred or "").lower())
    return bool(words) and words[0] in re.findall(r"[a-z0-9]+", truth.lower())


def prf(tp: int, fp: int, fn: int):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    args = ap.parse_args()
    res_dir = Path(args.results)

    gt = list(csv.DictReader(open(GT, encoding="utf-8-sig")))
    captures = sorted({r["capture"] for r in gt} | {"PROFINET-RT.pcap"})

    l2 = l2_counts()
    rows, details = [], []
    agg = dict(tp=0, fp=0, fn=0, l2=0, role_ok=0, role_n=0, cls_ok=0, cls_n=0)
    for k in ("ven_ok", "ven_n", "prod_ok", "prod_n", "fw_ok", "fw_n", "prod_false"):
        agg[k] = 0
    for cap in captures:
        f = res_dir / f"{cap}.json"
        if not f.exists():
            print(f"missing result for {cap}")
            continue
        pred = {d["ip"]: d for d in json.loads(f.read_text(encoding="utf-8"))["devices"]}
        g = [r for r in gt if r["capture"] == cap]
        truth = {r["ip"] for r in g if r["is_device"] == "Y"}
        tp = len(truth & pred.keys())
        fp_ips = sorted(pred.keys() - truth)
        fn_ips = sorted(truth - pred.keys())
        p, r_, f1 = prf(tp, len(fp_ips), len(fn_ips))

        role_rows = [r for r in g if r["is_device"] == "Y" and r["role"] in ("server", "client")]
        role_ok = 0
        for r in role_rows:
            pr = predicted_role(pred[r["ip"]]) if r["ip"] in pred else "missed"
            ok = pr == r["role"]
            role_ok += ok
            if not ok:
                details.append([cap, r["ip"], "role", r["role"], pr])
        for ip in fp_ips:
            details.append([cap, ip, "false_positive", "not a device", pred[ip].get("device_type")])
        for ip in fn_ips:
            details.append([cap, ip, "missed", "device", "-"])

        cls_rows = [
            r for r in g if r["is_device"] == "Y" and r["device_class"] != "Simulator (single host)"
        ]
        cls_ok = 0
        for r in cls_rows:
            pc = (
                CLASS_MAP.get(pred[r["ip"]].get("device_type") or "UNKNOWN", "IT/Other")
                if r["ip"] in pred
                else "missed"
            )
            ok = pc == r["device_class"]
            cls_ok += ok
            if not ok:
                details.append([cap, r["ip"], "class", r["device_class"], pc])

        # Identity: vendor (R4), product and firmware (R5)
        ven = dict(ok=0, n=0)
        prod = dict(ok=0, n=0)
        fw = dict(ok=0, n=0)
        prod_false = 0
        for r in g:
            if r["is_device"] != "Y":
                continue
            d = pred.get(r["ip"], {})
            if r["vendor"]:
                ven["n"] += 1
                if vendor_matches(d.get("vendor"), r["vendor"]):
                    ven["ok"] += 1
                else:
                    details.append([cap, r["ip"], "vendor", r["vendor"], d.get("vendor")])
            if r["product"]:
                prod["n"] += 1
                if _norm(d.get("product")) == _norm(r["product"]):
                    prod["ok"] += 1
                else:
                    details.append([cap, r["ip"], "product", r["product"], d.get("product")])
            elif d.get("product"):
                prod_false += 1
                details.append([cap, r["ip"], "false_product", "-", d.get("product")])
            if r["firmware"]:
                fw["n"] += 1
                if _norm(d.get("firmware")) == _norm(r["firmware"]):
                    fw["ok"] += 1
                else:
                    details.append([cap, r["ip"], "firmware", r["firmware"], d.get("firmware")])

        n_l2 = l2.get(cap, 0)
        r_l2 = tp / (len(truth) + n_l2) if len(truth) + n_l2 else 0.0
        acc = role_ok / len(role_rows) if role_rows else None
        cacc = cls_ok / len(cls_rows) if cls_rows else None
        rows.append(
            [
                cap,
                len(truth),
                len(pred),
                tp,
                len(fp_ips),
                len(fn_ips),
                f"{p:.3f}",
                f"{r_:.3f}",
                f"{f1:.3f}",
                n_l2,
                f"{r_l2:.3f}",
                f"{role_ok}/{len(role_rows)}",
                f"{acc:.3f}" if acc is not None else "-",
                f"{cls_ok}/{len(cls_rows)}",
                f"{cacc:.3f}" if cacc is not None else "-",
                "subset" if cap in SUBSETS else "independent",
                f"{ven['ok']}/{ven['n']}",
                f"{prod['ok']}/{prod['n']}",
                f"{fw['ok']}/{fw['n']}",
                prod_false,
            ]
        )
        if cap not in SUBSETS:
            agg["tp"] += tp
            agg["fp"] += len(fp_ips)
            agg["fn"] += len(fn_ips)
            agg["l2"] += n_l2
            agg["role_ok"] += role_ok
            agg["role_n"] += len(role_rows)
            agg["cls_ok"] += cls_ok
            agg["cls_n"] += len(cls_rows)
            agg["ven_ok"] += ven["ok"]
            agg["ven_n"] += ven["n"]
            agg["prod_ok"] += prod["ok"]
            agg["prod_n"] += prod["n"]
            agg["fw_ok"] += fw["ok"]
            agg["fw_n"] += fw["n"]
            agg["prod_false"] += prod_false

    p, r_, f1 = prf(agg["tp"], agg["fp"], agg["fn"])
    r_l2 = agg["tp"] / (agg["tp"] + agg["fn"] + agg["l2"])
    acc = agg["role_ok"] / agg["role_n"] if agg["role_n"] else 0.0
    cacc = agg["cls_ok"] / agg["cls_n"] if agg["cls_n"] else 0.0
    rows.append(
        [
            "ALL (independent)",
            agg["tp"] + agg["fn"],
            agg["tp"] + agg["fp"],
            agg["tp"],
            agg["fp"],
            agg["fn"],
            f"{p:.3f}",
            f"{r_:.3f}",
            f"{f1:.3f}",
            agg["l2"],
            f"{r_l2:.3f}",
            f"{agg['role_ok']}/{agg['role_n']}",
            f"{acc:.3f}",
            f"{agg['cls_ok']}/{agg['cls_n']}",
            f"{cacc:.3f}",
            "",
            f"{agg['ven_ok']}/{agg['ven_n']}",
            f"{agg['prod_ok']}/{agg['prod_n']}",
            f"{agg['fw_ok']}/{agg['fw_n']}",
            agg["prod_false"],
        ]
    )

    header = [
        "capture",
        "gt_devices",
        "predicted",
        "TP",
        "FP",
        "FN",
        "precision",
        "recall",
        "F1",
        "l2_only",
        "recall_incl_l2",
        "role_correct",
        "role_accuracy",
        "class_correct",
        "class_accuracy",
        "set",
        "vendor_correct",
        "product_correct",
        "firmware_correct",
        "false_product",
    ]
    with open(res_dir / "metrics.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    with open(res_dir / "errors.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["capture", "ip", "error", "ground_truth", "predicted"])
        w.writerows(details)

    widths = [30, 6, 6, 4, 4, 4, 6, 6, 6, 5, 6, 7, 6, 7, 6, 11, 7, 7, 7, 5]
    print("  ".join(h[:w].ljust(w) for h, w in zip(header, widths)))
    for row in rows:
        print("  ".join(str(c)[:w].ljust(w) for c, w in zip(row, widths)))
    print(f"\nWritten: {res_dir / 'metrics.csv'} and {res_dir / 'errors.csv'}")


if __name__ == "__main__":
    main()
