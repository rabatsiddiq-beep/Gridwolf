"""
gt_draft.py - build a DRAFT ground-truth sheet for one capture, using Wireshark's
own dissectors (tshark). This is independent of Gridwolf. Every row must still
be checked by hand in Wireshark before it becomes ground truth.

Usage:  python gt_draft.py <capture file> <output csv>
"""
import csv
import ipaddress
import os
import shutil
import subprocess
import sys
from collections import defaultdict

# Well-known ICS server ports (codebook rule R2)
ICS_PORTS = {
    502: "modbus", 102: "s7comm", 44818: "enip", 2222: "enip",
    20000: "dnp3", 2404: "iec104", 47808: "bacnet",
}
# Suggested class for a SERVER on that protocol (codebook rule R3)
SERVER_CLASS = {
    "modbus": "PLC", "s7comm": "PLC", "enip": "PLC",
    "dnp3": "RTU", "iec104": "RTU", "bacnet": "BACnet field device",
}
FIELDS = ["ip.src", "ip.dst", "eth.src", "eth.src.oui_resolved",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
          "tcp.flags.syn", "tcp.flags.ack", "_ws.col.Protocol"]


def find_tshark():
    t = shutil.which("tshark")
    if t:
        return t
    win = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(win):
        return win
    sys.exit("tshark not found - install Wireshark first")


def is_excluded(ip):
    """Codebook rule R1: not a device address."""
    a = ipaddress.ip_address(ip)
    return a.is_multicast or a.is_unspecified or ip.endswith(".255") or ip == "255.255.255.255"


def main(cap, out):
    cmd = [find_tshark(), "-r", cap, "-Y", "ip", "-T", "fields", "-E", "separator=\t"]
    for f in FIELDS:
        cmd += ["-e", f]
    rows = subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout.splitlines()

    sent = defaultdict(int)
    macs = defaultdict(set)
    vendor = {}
    protos = defaultdict(set)
    listens = defaultdict(set)     # ports this host serves on
    connects = defaultdict(set)    # ICS ports this host connects to
    seen = set()
    mac_ips = defaultdict(set)

    for line in rows:
        p = (line.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
        src, dst, smac, svend, tsp, tdp, usp, udp, syn, ack, proto = p
        src, dst = src.split(",")[0], dst.split(",")[0]   # ignore tunnelled inner headers
        if not src:
            continue
        seen.update([src, dst])
        sent[src] += 1
        if smac:
            macs[src].add(smac)
            mac_ips[smac].add(src)
            if svend:
                vendor[smac] = svend
        if proto:
            protos[src].add(proto)
        sport = int(tsp or usp or 0)
        dport = int(tdp or udp or 0)
        if tsp:  # TCP: handshake tells us who listens
            if syn in ("1", "True") and ack in ("0", "False"):
                connects[src].add(dport)
                listens[dst].add(dport)
                continue
            if syn in ("1", "True") and ack in ("1", "True"):
                listens[src].add(sport)
                continue
        # No handshake seen: the side using the well-known ICS port is the server
        if sport in ICS_PORTS and dport not in ICS_PORTS:
            listens[src].add(sport)
        elif dport in ICS_PORTS and sport not in ICS_PORTS:
            connects[src].add(dport)
        elif sport in ICS_PORTS and sport == dport:  # e.g. BACnet 47808<->47808
            protos[src].add(ICS_PORTS[sport] + " (peer)")

    out_rows = []
    for ip in sorted(seen, key=lambda x: ipaddress.ip_address(x)):
        if is_excluded(ip):
            continue
        ics_srv = sorted(p for p in listens[ip] if p in ICS_PORTS)
        ics_cli = sorted(p for p in connects[ip] if p in ICS_PORTS)
        if ics_srv and ics_cli:
            role = "both"
        elif ics_srv:
            role = "server"
        elif ics_cli:
            role = "client"
        else:
            role = "none-ICS"
        if ics_srv:
            klass = SERVER_CLASS[ICS_PORTS[ics_srv[0]]]
        elif ics_cli:
            klass = "HMI/SCADA (check: engineering WS?)"
        else:
            klass = "IT/Other"
        mac_list = sorted(macs[ip])
        shared = any(len(mac_ips[m]) > 1 for m in mac_list)
        vend = "; ".join(sorted({vendor.get(m, "") for m in mac_list} - {""}))
        out_rows.append({
            "capture": os.path.basename(cap),
            "ip": ip,
            "packets_sent": sent[ip],
            "observable": "Y" if sent[ip] > 0 else "N (receive-only)",
            "mac": "; ".join(mac_list),
            "mac_shared_by_many_ips": "Y (router? vendor unknown)" if shared else "N",
            "oui_vendor": "" if shared else vend,
            "protocols_seen": "; ".join(sorted(protos[ip])),
            "ics_ports_served": " ".join(map(str, ics_srv)),
            "ics_ports_connected_to": " ".join(map(str, ics_cli)),
            "suggested_role": role,
            "suggested_class": klass,
            # ---- columns YOU fill in after checking in Wireshark ----
            "is_device": "",
            "role": "",
            "device_class": "",
            "vendor": "",
            "product": "",
            "firmware": "",
            "confidence": "",
            "evidence": "",
            "notes": "",
        })

    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out_rows[0].keys()) if out_rows else ["capture"])
        w.writeheader()
        w.writerows(out_rows)
    obs = sum(1 for r in out_rows if r["observable"] == "Y")
    print(f"{os.path.basename(cap)}: {len(out_rows)} candidate IPs ({obs} send traffic) -> {out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
