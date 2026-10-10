"""
PCAP Processing Engine — Real packet analysis using Scapy.

Pipeline: Ingest → Dissect → Topology → Risk
"""

from __future__ import annotations

import ipaddress
import os
import logging
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict

try:
    from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, Ether, DNS, DNSQR, Raw

    SCAPY_AVAILABLE = True
    # pcapng support (Scapy 2.5+)
    try:
        from scapy.utils import PcapNgReader

        PCAPNG_AVAILABLE = True
    except ImportError:
        PCAPNG_AVAILABLE = False
except ImportError:
    SCAPY_AVAILABLE = False
    PCAPNG_AVAILABLE = False

from app.engine.protocol_parsers import (
    parse_modbus,
    parse_s7comm,
    parse_enip,
    parse_dnp3,
    parse_bacnet,
    parse_iec104,
    identify_protocol,
    OUI_VENDORS,
)
from app.engine.identity import (
    S7SzlCollector,
    bacnet_device_identity,
    bacnet_identity,
    parse_szl,
    s7_identity,
)

# Valid PCAP/PCAPNG magic bytes
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"  # pcap little-endian
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"  # pcap big-endian
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"  # pcap nanosecond LE
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"  # pcap nanosecond BE
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng Section Header Block
VALID_PCAP_MAGICS = {PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE}

logger = logging.getLogger(__name__)

# Well-known ICS *server* ports. The endpoint that uses one of these ports is the
# server (PLC/RTU/controller); the other endpoint is the client (HMI/workstation).
ICS_SERVER_PORTS = {
    502: "modbus",
    102: "s7comm",
    44818: "enip",
    2222: "enip",
    20000: "dnp3",
    2404: "iec104",
    47808: "bacnet",
}

# Device type assigned to a server, by protocol
SERVER_DEVICE_TYPE = {
    "modbus": "PLC",
    "s7comm": "PLC",
    "enip": "PLC",
    "dnp3": "RTU",
    "iec104": "RTU",
    "bacnet": "SENSOR",
}


def is_device_address(ip: str) -> bool:
    """True for a unicast host address; False for broadcast, multicast or unspecified."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    if ip == "255.255.255.255" or ip.endswith(".255"):
        return False
    return True


class PcapProcessor:
    """Process PCAP files and extract ICS/SCADA network topology."""

    def __init__(self):
        self.devices: dict[str, dict] = {}  # ip -> device info
        self.connections: dict[str, dict] = {}  # flow_key -> connection info
        self.protocol_events: list[dict] = []  # parsed ICS protocol events
        self.findings: list[dict] = []  # security findings
        self.packet_count = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.protocol_summary: dict[str, int] = defaultdict(int)
        self._szl = S7SzlCollector()

    def process_file(self, filepath: str) -> dict:
        """Process a PCAP file and return analysis results."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Install with: pip install scapy")

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        # Stage 1: Ingest — validate file before processing
        file_size = os.path.getsize(filepath)
        if file_size < 24:
            raise RuntimeError(f"PCAP file too small ({file_size} bytes) — not a valid capture")

        # Check magic bytes to determine format
        with open(filepath, "rb") as fh:
            magic = fh.read(4)

        is_pcapng = magic == PCAPNG_MAGIC
        is_pcap = magic in VALID_PCAP_MAGICS

        if not is_pcap and not is_pcapng:
            raise RuntimeError(
                f"Not a valid PCAP/PCAPNG file (magic: {magic.hex()}). "
                f"File may be corrupted during upload."
            )

        logger.info(
            f"Processing {'pcapng' if is_pcapng else 'pcap'}: {filepath} ({file_size:,} bytes)"
        )

        # Read packets using the appropriate reader
        self._read_packets(filepath, file_size, is_pcapng)

        logger.info(f"Parsed {self.packet_count} packets, {len(self.devices)} devices")

        # Assign roles and device types from everything observed
        self._finalize_classification()
        self._finalize_identity()

        # Stage 4: Risk assessment
        self._run_risk_assessment()

        return {
            "packet_count": self.packet_count,
            "file_size": file_size,
            "duration_seconds": (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "devices": list(self.devices.values()),
            "connections": list(self.connections.values()),
            "protocol_events": self.protocol_events,
            "findings": self.findings,
            "protocol_summary": dict(self.protocol_summary),
        }

    def _read_packets(self, filepath: str, file_size: int, is_pcapng: bool):
        """Read packets from a PCAP or PCAPNG file using the best available reader."""
        # Strategy: try streaming reader first, then fall back to rdpcap
        readers_to_try = []

        if is_pcapng:
            if PCAPNG_AVAILABLE:
                readers_to_try.append(("PcapNgReader", lambda: PcapNgReader(filepath)))
            # rdpcap in Scapy 2.5+ handles pcapng too
            readers_to_try.append(("rdpcap", None))
        else:
            # For pcap: stream large files, load small ones
            if file_size > 10 * 1024 * 1024:  # > 10 MB
                readers_to_try.append(("PcapReader", lambda: PcapReader(filepath)))
            readers_to_try.append(("rdpcap", None))

        last_error = None
        for reader_name, reader_factory in readers_to_try:
            # Reset state before each attempt to prevent duplicates
            self.devices.clear()
            self.connections.clear()
            self.protocol_events.clear()
            self.findings.clear()
            self.packet_count = 0
            self.start_time = None
            self.end_time = None
            self.protocol_summary.clear()
            self._szl = S7SzlCollector()

            try:
                if reader_factory:
                    logger.info(f"Trying {reader_name}...")
                    reader = reader_factory()
                    for pkt in reader:
                        self._process_packet(pkt)
                    reader.close()
                else:
                    logger.info("Trying rdpcap (loads entire file into memory)...")
                    packets = rdpcap(filepath)
                    for pkt in packets:
                        self._process_packet(pkt)

                logger.info(f"{reader_name} succeeded: {self.packet_count} packets")
                return  # success
            except Exception as e:
                last_error = e
                logger.warning(f"{reader_name} failed: {e}")
                continue

        raise RuntimeError(f"Could not read capture file with any parser. Last error: {last_error}")

    def _process_packet(self, pkt):
        """Process a single packet — Stage 2 (Dissect) + Stage 3 (Topology)."""
        self.packet_count += 1

        # Extract timestamp
        try:
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
        except (ValueError, OSError):
            ts = datetime.now(timezone.utc)

        if self.start_time is None or ts < self.start_time:
            self.start_time = ts
        if self.end_time is None or ts > self.end_time:
            self.end_time = ts

        # Extract MAC addresses for OUI lookup
        src_mac = None
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Stage 3: Update topology (devices).
        # Only a host that SENDS traffic is recorded as a device: an address that is
        # only ever a destination may not exist (e.g. an unanswered SYN or ping).
        # Broadcast, multicast and unspecified addresses are never devices.
        if is_device_address(src_ip):
            self._update_device(src_ip, src_mac, ts)

        # Determine transport and ports
        sport = dport = 0
        transport = "OTHER"
        payload = b""

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            transport = "TCP"
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            transport = "UDP"
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)

        # Identify ICS protocol
        protocol = identify_protocol(dport, sport, payload)
        self.protocol_summary[protocol] += 1

        # Stage 2: Deep protocol dissection
        events: list[dict] = []
        if protocol != "other" and payload:
            events = self._dissect_protocol(protocol, src_ip, dst_ip, sport, dport, payload, ts)
            self.protocol_events.extend(events)
            self._extract_identity(protocol, src_ip, dst_ip, payload)

        # Update device protocols (only for hosts already recorded as devices)
        if protocol != "other":
            for ip in (src_ip, dst_ip):
                dev = self.devices.get(ip)
                if dev is not None and protocol not in dev["protocols"]:
                    dev["protocols"].append(protocol)

        # Server/client roles: decided from the ICS port, only on packets that carry
        # application data (so an unanswered SYN does not create a role).
        if protocol in SERVER_DEVICE_TYPE and payload:
            server_ip, client_ip, server_port = self._ics_endpoints(
                sport, dport, src_ip, dst_ip, events
            )
            if server_ip:
                self._record_role(server_ip, protocol, "server")
                server = self.devices.get(server_ip)
                if server is not None and server_port not in server["open_ports"]:
                    server["open_ports"].append(server_port)
            if client_ip:
                self._record_role(client_ip, protocol, "client")

        # Update connection tracking
        flow_key = f"{src_ip}:{sport}->{dst_ip}:{dport}"
        if flow_key not in self.connections:
            self.connections[flow_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "protocol": protocol,
                "transport": transport,
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": ts.isoformat(),
                "last_seen": ts.isoformat(),
                "is_ics": protocol != "other",
            }
        conn = self.connections[flow_key]
        conn["packet_count"] += 1
        conn["byte_count"] += len(pkt)
        conn["last_seen"] = ts.isoformat()

        # DNS analysis for C2 detection
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            self._analyze_dns(src_ip, qname, ts)

    def _update_device(self, ip: str, mac: Optional[str], ts: datetime):
        """Update or create a device entry."""
        if ip not in self.devices:
            vendor = None
            if mac:
                oui = mac[:8].upper().replace(":", "-")
                vendor = OUI_VENDORS.get(oui)

            self.devices[ip] = {
                "ip_address": ip,
                "mac_address": mac,
                "hostname": None,
                "vendor": vendor,
                "model": None,
                "firmware_version": None,
                "device_type": "UNKNOWN",
                "purdue_level": "UNKNOWN",
                "protocols": [],
                "open_ports": [],
                "confidence": 1,
                "first_seen": ts.isoformat(),
                "last_seen": ts.isoformat(),
                "packet_count": 0,
                "properties": {},
            }
        dev = self.devices[ip]
        dev["packet_count"] += 1
        dev["last_seen"] = ts.isoformat()
        if mac and not dev["mac_address"]:
            dev["mac_address"] = mac
            oui = mac[:8].upper().replace(":", "-")
            dev["vendor"] = OUI_VENDORS.get(oui, dev.get("vendor"))

    def _extract_identity(self, protocol: str, src_ip: str, dst_ip: str, payload: bytes):
        """Record identity a device discloses about itself (iteration 2a, rule 1).

        Only responses are used, and they describe their SENDER: an S7 'Read SZL'
        response or a BACnet ReadProperty ComplexACK on the Device object.
        """
        dev = self.devices.get(src_ip)
        if dev is None:
            return
        found: dict = {}
        source = ""
        if protocol == "s7comm":
            block = self._szl.feed(src_ip, dst_ip, payload)
            if block:
                found = parse_szl(block)
                szl_id = int.from_bytes(block[:2], "big") if len(block) >= 2 else 0
                source = f"s7comm SZL 0x{szl_id:04X}"
        elif protocol == "bacnet":
            prop = bacnet_identity(payload)
            if prop:
                found = {prop[0]: prop[1]}
                source = f"bacnet ReadProperty {prop[0]}"
        if not found:
            return
        ident = dev["properties"].setdefault("identity", {"protocol": protocol, "fields": {}})
        for key, value in found.items():
            ident["fields"].setdefault(key, value)
        evidence = ident.setdefault("evidence", [])
        if not any(e.startswith(source + " (") for e in evidence):  # first packet per source
            evidence.append(f"{source} (packet {self.packet_count})")

    def _finalize_identity(self) -> None:
        """Turn collected identity fields into vendor, model and firmware."""
        for dev in self.devices.values():
            ident = dev["properties"].get("identity")
            if not ident:
                continue
            if ident["protocol"] == "s7comm":
                result = s7_identity(ident["fields"])
            else:
                result = bacnet_device_identity(ident["fields"])
            if result["product"]:
                dev["model"] = result["product"]
                dev["confidence"] = max(dev.get("confidence", 1), 5)
            if result["firmware"]:
                dev["firmware_version"] = result["firmware"]
            if result["vendor"]:
                # Vendor stated by the device itself outranks the MAC OUI (codebook R4/R5)
                dev["properties"]["oui_vendor"] = dev.get("vendor")
                dev["vendor"] = result["vendor"]
                dev["properties"]["vendor_source"] = ident["protocol"]

    def _dissect_protocol(
        self,
        protocol: str,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        payload: bytes,
        ts: datetime,
    ) -> list[dict]:
        """Deep protocol dissection — parse ICS protocol payloads."""
        events = []
        try:
            if protocol == "modbus":
                events = parse_modbus(payload, src_ip, dst_ip, ts)
            elif protocol == "s7comm":
                events = parse_s7comm(payload, src_ip, dst_ip, ts)
            elif protocol == "enip":
                events = parse_enip(payload, src_ip, dst_ip, ts)
            elif protocol == "dnp3":
                events = parse_dnp3(payload, src_ip, dst_ip, ts)
            elif protocol == "bacnet":
                events = parse_bacnet(payload, src_ip, dst_ip, ts)
            elif protocol == "iec104":
                events = parse_iec104(payload, src_ip, dst_ip, ts)
        except Exception as e:
            logger.debug(f"Protocol parse error ({protocol}): {e}")

        return events

    @staticmethod
    def _ics_endpoints(
        sport: int, dport: int, src_ip: str, dst_ip: str, events: list[dict]
    ) -> tuple[Optional[str], Optional[str], int]:
        """Return (server_ip, client_ip, server_port) for one ICS packet.

        The endpoint using the well-known ICS port is the server. When both sides use
        the same well-known port (e.g. BACnet 47808 <-> 47808), the parsed message
        direction decides: a sender that answers is the server, a sender that asks is
        the client. Parser 'role' values describe the SENDER of the packet.
        """
        s_srv = sport in ICS_SERVER_PORTS
        d_srv = dport in ICS_SERVER_PORTS
        if d_srv and not s_srv:
            return dst_ip, src_ip, dport
        if s_srv and not d_srv:
            return src_ip, dst_ip, sport
        if s_srv and d_srv:
            for event in events:
                role = event.get("role")
                if role in ("slave", "server"):
                    return src_ip, dst_ip, sport
                if role in ("master", "client"):
                    return dst_ip, src_ip, dport
        return None, None, 0

    def _record_role(self, ip: str, protocol: str, role: str) -> None:
        """Remember that a device acted as server or client for a protocol."""
        dev = self.devices.get(ip)
        if dev is None:
            return
        roles = dev["properties"].setdefault("ics_roles", {})
        protocols = roles.setdefault(role, [])
        if protocol not in protocols:
            protocols.append(protocol)

    def _finalize_classification(self) -> None:
        """Set role, device type and Purdue level once all packets have been seen."""
        for dev in self.devices.values():
            roles = dev["properties"].get("ics_roles", {})
            served = roles.get("server", [])
            clients = roles.get("client", [])
            if served and clients:
                dev["properties"]["ics_role"] = "both"
            elif served:
                dev["properties"]["ics_role"] = "server"
            elif clients:
                dev["properties"]["ics_role"] = "client"

            if served:
                dev["device_type"] = SERVER_DEVICE_TYPE[served[0]]
                dev["purdue_level"] = "L1"
                dev["confidence"] = max(dev.get("confidence", 1), 4)
            elif clients:
                dev["device_type"] = "WORKSTATION" if clients == ["bacnet"] else "HMI"
                dev["purdue_level"] = "L2"
                dev["confidence"] = max(dev.get("confidence", 1), 3)

    def _analyze_dns(self, src_ip: str, qname: str, ts: datetime):
        """Analyze DNS queries for potential exfiltration."""
        import math

        # Shannon entropy calculation
        if len(qname) > 0:
            prob = [float(qname.count(c)) / len(qname) for c in set(qname)]
            entropy = -sum(p * math.log2(p) for p in prob if p > 0)

            # High entropy + long subdomain = potential exfiltration
            subdomain = qname.split(".")[0] if "." in qname else qname
            if entropy > 4.0 and len(subdomain) > 20:
                self.findings.append(
                    {
                        "finding_type": "dns_exfil",
                        "severity": "high",
                        "title": f"Potential DNS Exfiltration from {src_ip}",
                        "description": f"High-entropy DNS query detected: {qname} (entropy: {entropy:.2f})",
                        "src_ip": src_ip,
                        "protocol": "dns",
                        "confidence": min(int(entropy * 20), 100),
                        "evidence": {
                            "query": qname,
                            "entropy": round(entropy, 2),
                            "subdomain_length": len(subdomain),
                        },
                    }
                )

    def _run_risk_assessment(self):
        """Stage 4: Run risk assessment on discovered topology."""
        # Check for Purdue violations (cross-zone communication)
        for flow_key, conn in self.connections.items():
            src_dev = self.devices.get(conn["src_ip"], {})
            dst_dev = self.devices.get(conn["dst_ip"], {})
            src_level = src_dev.get("purdue_level", "UNKNOWN")
            dst_level = dst_dev.get("purdue_level", "UNKNOWN")

            if src_level != "UNKNOWN" and dst_level != "UNKNOWN":
                # L3 → L1 direct (bypassing L2)
                if src_level == "L3" and dst_level == "L1":
                    self.findings.append(
                        {
                            "finding_type": "purdue_violation",
                            "severity": "critical",
                            "title": f"Purdue Violation: {src_level}→{dst_level} ({conn['src_ip']} → {conn['dst_ip']})",
                            "description": f"Direct communication from {src_level} to {dst_level} bypassing supervisory layer",
                            "src_ip": conn["src_ip"],
                            "dst_ip": conn["dst_ip"],
                            "protocol": conn["protocol"],
                            "confidence": 90,
                            "mitre_technique": "T0886",
                        }
                    )
                # DMZ → L1/L2 (external zone to control zone)
                elif src_level == "DMZ" and dst_level in ("L1", "L2"):
                    self.findings.append(
                        {
                            "finding_type": "purdue_violation",
                            "severity": "critical",
                            "title": f"Purdue Violation: DMZ→{dst_level} ({conn['src_ip']} → {conn['dst_ip']})",
                            "description": f"Communication from DMZ to control zone ({dst_level})",
                            "src_ip": conn["src_ip"],
                            "dst_ip": conn["dst_ip"],
                            "protocol": conn["protocol"],
                            "confidence": 95,
                            "mitre_technique": "T0886",
                        }
                    )

        # Check for write operations (dangerous control paths)
        for event in self.protocol_events:
            if event.get("is_write") or event.get("is_critical"):
                self.findings.append(
                    {
                        "finding_type": "write_path",
                        "severity": "high" if event.get("is_write") else "critical",
                        "title": f"Write/Program Path: {event.get('function_name', 'Unknown')}",
                        "description": f"{event['protocol'].upper()} write operation from {event['src_ip']} to {event['dst_ip']}",
                        "src_ip": event["src_ip"],
                        "dst_ip": event["dst_ip"],
                        "protocol": event["protocol"],
                        "confidence": 85,
                        "evidence": event.get("details", {}),
                    }
                )

        # Check for default credential indicators (common ICS ports without auth)
        for ip, dev in self.devices.items():
            ports = dev.get("open_ports", [])
            if 23 in ports:  # Telnet
                self.findings.append(
                    {
                        "finding_type": "default_credential",
                        "severity": "high",
                        "title": f"Telnet Service Enabled on {ip}",
                        "description": f"Plaintext authentication protocol on {dev.get('hostname', ip)}",
                        "src_ip": ip,
                        "confidence": 80,
                        "remediation": "Disable Telnet and enable SSH",
                    }
                )

        logger.info(f"Risk assessment complete: {len(self.findings)} findings generated")
