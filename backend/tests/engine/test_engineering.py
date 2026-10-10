"""Tests for engineering-workstation detection (rule 2) and vendor OT protocols (rule 3).

Packets are built from the protocol layouts; no capture files are needed.
"""

from __future__ import annotations

import struct

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

from app.engine.engineering import engineering_action
from app.engine.pcap_processor import PcapProcessor
from app.engine.vendor_protocols import is_cola, vendor_endpoints

# ── builders ────────────────────────────────────────────────────────────────


def tpkt(s7: bytes) -> bytes:
    cotp = bytes([0x02, 0xF0, 0x80])
    return struct.pack(">BBH", 3, 0, 4 + len(cotp) + len(s7)) + cotp + s7


def s7_job(func: int) -> bytes:
    param = bytes([func]) + b"\x00" * 7
    return tpkt(struct.pack(">BBHHHH", 0x32, 0x01, 0, 1, len(param), 0) + param)


def s7_userdata(group: int, subfunc: int, data: bytes = b"", request=True) -> bytes:
    type_group = (0x40 if request else 0x80) | group
    param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, type_group, subfunc, 0x00])
    return tpkt(struct.pack(">BBHHHH", 0x32, 0x07, 0, 1, len(param), len(data)) + param + data)


def szl_request(szl_id: int) -> bytes:
    return s7_userdata(4, 1, struct.pack(">BBHHH", 0xFF, 0x09, 4, szl_id, 0))


def modbus(fc: int) -> bytes:
    return struct.pack(">HHHBB", 1, 0, 2, 1, fc)


def enip(command: int, data: bytes = b"") -> bytes:
    return struct.pack("<HHII8sI", command, len(data), 1, 0, b"\x00" * 8, 0) + data


def send_rr(cip: bytes) -> bytes:
    cpf = struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0, 0)
    cpf += struct.pack("<HH", 0xB2, len(cip)) + cip
    return enip(0x006F, cpf)


def cip(service: int, path: bytes, data: bytes = b"") -> bytes:
    return bytes([service, len(path) // 2]) + path + data


PCCC_DIAG = cip(
    0x4B, b"\x20\x67\x24\x01", b"\x07\x01\x00\x01\x02\x03\x04" + b"\x06\x00\x01\x00\x03"
)


def bacnet(apdu: bytes, function=0x0A) -> bytes:
    body = b"\x01\x04" + apdu  # NPDU: version 1, expecting reply
    return struct.pack(">BBH", 0x81, function, 4 + len(body)) + body


def read_property(obj_type: int, prop: int) -> bytes:
    obj = struct.pack(">I", (obj_type << 22) | 1)
    return bytes([0x00, 0x05, 0x01, 0x0C]) + b"\x0c" + obj + bytes([0x19, prop])


# ── rule 2: engineering actions ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "protocol,payload,to_server,expected",
    [
        ("s7comm", s7_job(0x1A), True, "s7comm Request download"),
        ("s7comm", s7_job(0x29), True, "s7comm PLC stop"),
        ("s7comm", s7_userdata(3, 1), True, "s7comm block function (subfunction 1)"),
        ("s7comm", szl_request(0x0011), True, "s7comm read SZL 0x0011 (module identification)"),
        ("s7comm", szl_request(0x00A0), True, "s7comm read SZL 0x00A0 (diagnostic buffer)"),
        ("modbus", modbus(43), True, "modbus FC43 Read Device Identification"),
        ("modbus", modbus(8), True, "modbus FC8 Diagnostics"),
        ("enip", enip(0x0063), True, "enip ListIdentity"),
        ("enip", send_rr(PCCC_DIAG), True, "pccc Diagnostic Status"),
        ("enip", send_rr(cip(0x01, b"\x20\x01\x24\x01")), True, "cip Identity object read"),
        ("bacnet", bacnet(read_property(8, 70)), True, "bacnet ReadProperty model_name"),
        ("bacnet", bacnet(b"", function=0x02), True, "bacnet Read-BDT"),
        ("bacnet", bacnet(bytes([0x00, 0x05, 0x01, 20])), True, "bacnet ReinitializeDevice"),
    ],
)
def test_engineering_actions(protocol, payload, to_server, expected):
    assert engineering_action(protocol, payload, to_server) == expected


@pytest.mark.parametrize(
    "protocol,payload,to_server",
    [
        ("s7comm", s7_job(0x04), True),  # Read Var: HMI polling
        ("s7comm", szl_request(0x0424), True),  # CPU mode: HMIs read this
        ("s7comm", szl_request(0x0132), True),  # communication status
        ("s7comm", s7_userdata(3, 1, request=False), False),  # a response
        ("modbus", modbus(3), True),  # Read Holding Registers
        ("modbus", modbus(43), False),  # FC43 response from the server
        ("enip", enip(0x0063, b"\x01\x00" + b"\x00" * 30), False),  # ListIdentity reply
        ("enip", send_rr(cip(0x4C, b"\x91\x03abc\x00")), True),  # Read Tag
        ("bacnet", bacnet(read_property(0, 85)), True),  # present-value of an input
        ("bacnet", bacnet(b"", function=0x05), True),  # Register-Foreign-Device
        ("modbus", b"\x00\x01", True),
        ("enip", b"\x6f\x00" + b"\x00" * 30, True),
        ("bacnet", b"\x81\x0a\x00\x06\x01\x04", True),
    ],
)
def test_process_reads_responses_and_junk_are_not_engineering(protocol, payload, to_server):
    assert engineering_action(protocol, payload, to_server) is None


# ── rule 3: vendor protocols ────────────────────────────────────────────────


def test_cola_telegrams():
    assert is_cola(b"\x02sRN DeviceIdent\x03")
    assert is_cola(b"\x02\x02\x02\x02\x00\x00\x00\x03sRN")
    assert not is_cola(b"GET / HTTP/1.1\r\n")
    assert not is_cola(b"\x02xyz\x03")


def test_vendor_endpoints():
    assert vendor_endpoints(2111, 50000, "s", "c", b"\x02sAN mLMPsetscancfg 0\x03") == (
        "sick-cola",
        "s",
        "c",
    )
    assert vendor_endpoints(50000, 2111, "c", "s", b"\x00\x01binary") is None  # not CoLa
    assert vendor_endpoints(50000, 5413, "c", "s", b"\x5f\x00") == ("suitelink", "s", "c")
    assert vendor_endpoints(50000, 8000, "c", "s", b"0000") is None  # generic port


# ── through the processor ───────────────────────────────────────────────────


def _run(tmp_path, packets):
    path = tmp_path / "t.pcap"
    wrpcap(str(path), packets)
    return {d["ip_address"]: d for d in PcapProcessor().process_file(str(path))["devices"]}


def tcp(src, dst, sport, dport, payload):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(payload)


def test_modbus_identification_makes_an_engineering_workstation(tmp_path):
    plc, hmi, ews = "10.0.0.3", "10.0.0.9", "10.0.0.57"
    devs = _run(
        tmp_path,
        [
            tcp(hmi, plc, 40000, 502, modbus(3)),
            tcp(plc, hmi, 502, 40000, modbus(3)),
            tcp(ews, plc, 40001, 502, modbus(43)),
            tcp(plc, ews, 502, 40001, modbus(43)),
        ],
    )
    assert devs[hmi]["device_type"] == "HMI"
    assert devs[ews]["device_type"] == "ENGINEERING_WORKSTATION"
    assert devs[ews]["properties"]["ics_role"] == "client"
    assert devs[plc]["device_type"] == "PLC"  # its FC43 response is not an action


def test_vendor_protocols_type_only_otherwise_untyped_hosts(tmp_path):
    scada, plc, sick, station, label = (
        "141.81.0.10",
        "141.81.0.20",
        "141.81.0.42",
        "141.81.0.181",
        "141.81.0.49",
    )
    devs = _run(
        tmp_path,
        [
            tcp(scada, plc, 40000, 502, modbus(3)),
            tcp(plc, scada, 502, 40000, modbus(3)),
            tcp(scada, sick, 40001, 2111, b"\x02sRN DeviceIdent\x03"),
            tcp(sick, scada, 2111, 40001, b"\x02sRA DeviceIdent 6 CLV63x\x03"),
            tcp(station, scada, 40002, 5413, b"\x5f\x00\xa0\xe1"),
            tcp(scada, station, 5413, 40002, b"\x5f\x00\xa0\xe1"),
            tcp(scada, label, 40003, 8000, b"0000"),
            tcp(label, scada, 8000, 40003, b"0000\x06"),
        ],
    )
    assert devs[sick]["device_type"] == "OT_DEVICE" and devs[sick]["purdue_level"] == "L1"
    assert devs[station]["device_type"] == "HMI"
    assert devs[scada]["device_type"] == "HMI"  # Modbus client role decides first
    assert devs[scada]["properties"]["ics_role"] == "client"  # SuiteLink is not an R2 role
    assert "ics_role" not in devs[station]["properties"]
    assert devs[label]["device_type"] == "UNKNOWN"  # port 8000 is generic


def test_bacnet_identity_reader_is_an_engineering_workstation(tmp_path):
    ctrl, ws = "10.1.1.165", "10.1.1.167"
    req = bacnet(read_property(8, 121))
    ack = struct.pack(">BBH", 0x81, 0x0A, 4 + 2 + 3) + b"\x01\x00" + b"\x20\x01\x0c"
    pkts = [
        Ether() / IP(src=ws, dst=ctrl) / UDP(sport=47808, dport=47808) / Raw(req),
        Ether() / IP(src=ctrl, dst=ws) / UDP(sport=47808, dport=47808) / Raw(ack),
    ]
    devs = _run(tmp_path, pkts)
    assert devs[ws]["device_type"] == "ENGINEERING_WORKSTATION"
    assert devs[ctrl]["device_type"] == "SENSOR"
