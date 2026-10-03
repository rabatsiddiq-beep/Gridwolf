"""
run_engine.py - run the Gridwolf analysis engine headlessly on the thesis captures.

No UI, no database: the PCAP processor is called directly, so the same input always
gives the same output. One JSON file per capture is written to --out.

Usage (from the repo root, with the backend virtual environment active):
    python docs/thesis/scripts/run_engine.py --pcaps <ITI pcaps folder> --out docs/thesis/results/<label>
"""

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "backend"))

from app.engine.pcap_processor import PcapProcessor  # noqa: E402

# Same 12 captures as docs/thesis/datasets.csv (relative to the ITI pcaps folder)
CAPTURES = [
    "Combined/Plant1.pcap",
    "ModbusTCP/ModbusTCP.pcap",
    "ModbusTCP/modbus_test_data_part1.pcap",
    "s7/tia_s300_goOnline.pcapng",
    "s7/s7comm_reading_plc_status.pcap",
    "s7/wincc_s400_production.pcapng",
    "EthernetIP/EthernetIP-CIP.pcap",
    "CIP/cip_unclean.pcap",
    "IEC60870-5-104/090813_diverse.pcap",
    "BACnet/bacnet_test.pcap",
    "dnp3/full_exchange.pcap",
    "profinet/PROFINET-RT-DCP/PROFINET-RT.pcap",
]


def git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except OSError:
        return "unknown"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcaps", required=True, help="ITI pcaps folder")
    ap.add_argument("--out", required=True, help="output folder for JSON results")
    args = ap.parse_args()

    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("scapy").setLevel(logging.ERROR)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    commit = git_commit()

    for rel in CAPTURES:
        path = Path(args.pcaps) / rel
        res = PcapProcessor().process_file(str(path))
        devices = []
        for d in sorted(res["devices"], key=lambda x: x["ip_address"]):
            devices.append(
                {
                    "ip": d["ip_address"],
                    "mac": d.get("mac_address"),
                    "vendor": d.get("vendor"),
                    "device_type": d.get("device_type"),
                    "role": (d.get("properties") or {}).get("ics_role"),
                    "purdue_level": d.get("purdue_level"),
                    "protocols": d.get("protocols", []),
                    "open_ports": sorted(d.get("open_ports", [])),
                }
            )
        record = {
            "capture": path.name,
            "engine_commit": commit,
            "packet_count": res["packet_count"],
            "device_count": len(devices),
            "finding_count": len(res["findings"]),
            "devices": devices,
        }
        (out / f"{path.name}.json").write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )
        print(f"{path.name:40s} {len(devices):3d} devices  (engine {commit})")


if __name__ == "__main__":
    main()
