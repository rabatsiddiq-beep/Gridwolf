"""
robustness.py - does the engine survive malformed and hostile input? (Table 5.7)

Three groups of test cases, all deterministic (fixed random seed):

  1. Public fuzzed captures from the Zeek Modbus test suite in the ITI collection
     (pcaps/bro/modbus/fuzz-72.pcap, fuzz-1011.pcap).
  2. Mutated captures: the ICS payloads of one capture per protocol are corrupted in
     five ways (byte flips, truncation, junk extension, zero-fill, a mix of all four),
     with IP/TCP length fields left as they were, so headers and payloads disagree.
  3. Damaged files: a capture cut part-way through a packet, a file of random bytes,
     and an empty file.

Outcome per case:
  processed  the engine read the file and returned results (malformed packets skipped)
  rejected   the engine refused the file with its input-validation error (expected for
             random bytes and empty files)
  crash      any other exception: a robustness failure

Usage (repo root, backend virtual environment active):
    python docs/thesis/scripts/robustness.py --pcaps <ITI pcaps folder> --out docs/thesis/results/<label>
"""

from __future__ import annotations

import argparse
import csv
import logging
import random
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "backend"))

from scapy.all import Raw, rdpcap, wrpcap  # noqa: E402

from app.engine.pcap_processor import PcapProcessor  # noqa: E402

SEED = 2026
MAX_PACKETS = 2000  # per mutated capture, to keep the run short

FUZZED = ["bro/modbus/fuzz-72.pcap", "bro/modbus/fuzz-1011.pcap"]
PER_PROTOCOL = {
    "modbus": "ModbusTCP/modbus_test_data_part1.pcap",
    "s7comm": "s7/tia_s300_goOnline.pcapng",
    "enip": "CIP/cip_unclean.pcap",
    "dnp3": "dnp3/full_exchange.pcap",
    "iec104": "IEC60870-5-104/090813_diverse.pcap",
    "bacnet": "BACnet/bacnet_test.pcap",
}
MUTATIONS = ["flip", "truncate", "extend", "zero", "mixed"]


def mutate(payload: bytes, mode: str, rng: random.Random) -> bytes:
    data = bytearray(payload)
    if mode == "mixed":
        mode = rng.choice(MUTATIONS[:-1])
    if mode == "flip":
        for _ in range(max(1, len(data) // 10)):
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
    elif mode == "truncate":
        data = data[: rng.randrange(len(data))]
    elif mode == "extend":
        data += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
    elif mode == "zero":
        start = rng.randrange(len(data))
        for i in range(start, min(len(data), start + rng.randrange(1, 16))):
            data[i] = 0
    return bytes(data)


def run(path: Path) -> dict:
    try:
        res = PcapProcessor().process_file(str(path))
        return {
            "outcome": "processed",
            "packets_processed": res["packet_count"],
            "devices": len(res["devices"]),
            "events": len(res["protocol_events"]),
            "packet_errors": res.get("packet_errors", 0),
            "error": "",
        }
    except Exception as e:  # noqa: BLE001 - every failure is recorded, not raised
        msg = str(e)
        rejected = isinstance(e, RuntimeError) and ("Not a valid PCAP" in msg or "too small" in msg)
        return {
            "outcome": "rejected" if rejected else "crash",
            "packets_processed": 0,
            "devices": 0,
            "events": 0,
            "packet_errors": 0,
            "error": f"{type(e).__name__}: {msg[:120]}",
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcaps", required=True, help="ITI pcaps folder")
    ap.add_argument("--out", required=True, help="results folder for robustness.csv")
    args = ap.parse_args()
    pcaps, out = Path(args.pcaps), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    logging.disable(logging.WARNING)
    rng = random.Random(SEED)
    rows = []

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        for rel in FUZZED:
            path = pcaps / rel
            if not path.exists():
                print(
                    f"missing {rel}: run 'git sparse-checkout add pcaps/bro/modbus' in the ITI clone"
                )
                continue
            rows.append({"case": path.name, "group": "fuzzed (Zeek test suite)",
                         "protocol": "modbus", "mutation": "-", **run(path)})  # fmt: skip

        for proto, rel in PER_PROTOCOL.items():
            packets = rdpcap(str(pcaps / rel), count=MAX_PACKETS)
            for mode in MUTATIONS:
                changed = 0
                mutated = []
                for pkt in packets:
                    pkt = pkt.copy()
                    if pkt.haslayer(Raw) and len(pkt[Raw].load) > 0:
                        pkt[Raw].load = mutate(bytes(pkt[Raw].load), mode, rng)
                        changed += 1
                    mutated.append(pkt)
                path = tmp / f"{proto}-{mode}.pcap"
                wrpcap(str(path), mutated)
                rows.append({"case": f"{Path(rel).name} [{mode}]", "group": "mutated payloads",
                             "protocol": proto, "mutation": f"{mode} ({changed} payloads)",
                             **run(path)})  # fmt: skip

        src = (pcaps / PER_PROTOCOL["modbus"]).read_bytes()
        cut = tmp / "truncated.pcap"
        cut.write_bytes(src[: int(len(src) * 0.6)])
        rows.append({"case": "modbus_test_data_part1.pcap cut at 60%", "group": "damaged file",
                     "protocol": "modbus", "mutation": "file truncated mid-packet", **run(cut)})  # fmt: skip
        junk = tmp / "random.pcap"
        junk.write_bytes(bytes(rng.randrange(256) for _ in range(4096)))
        rows.append({"case": "random bytes", "group": "damaged file", "protocol": "-",
                     "mutation": "not a capture", **run(junk)})  # fmt: skip
        empty = tmp / "empty.pcap"
        empty.write_bytes(b"")
        rows.append({"case": "empty file", "group": "damaged file", "protocol": "-",
                     "mutation": "0 bytes", **run(empty)})  # fmt: skip

    fields = ["case", "group", "protocol", "mutation", "outcome", "packets_processed",
              "devices", "events", "packet_errors", "error"]  # fmt: skip
    with open(out / "robustness.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    for r in rows:
        print(
            f"{r['case'][:44]:44s} {r['outcome']:10s} {r['packets_processed']:6d} pkts "
            f"{r['packet_errors']:4d} skipped  {r['error'][:40]}"
        )
    counts = {
        k: sum(1 for r in rows if r["outcome"] == k) for k in ("processed", "rejected", "crash")
    }
    print(
        f"\n{len(rows)} cases: {counts['processed']} processed, {counts['rejected']} rejected "
        f"cleanly, {counts['crash']} crashed  ->  {out / 'robustness.csv'}"
    )


if __name__ == "__main__":
    main()
