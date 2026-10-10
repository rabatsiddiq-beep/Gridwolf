"""Tests for identity extraction from S7comm SZL and BACnet ReadProperty responses.

Packets are built byte by byte from the protocol layouts, so the tests do not
depend on any capture file. Product names and versions are illustrative.
"""

from __future__ import annotations

import struct

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

from app.engine.identity import (
    S7SzlCollector,
    bacnet_device_identity,
    bacnet_identity,
    parse_szl,
    s7_identity,
)
from app.engine.pcap_processor import PcapProcessor

# ── S7comm builders ─────────────────────────────────────────────────────────


def s7_userdata(param: bytes, data: bytes) -> bytes:
    s7 = struct.pack(">BBHHHH", 0x32, 0x07, 0, 1, len(param), len(data)) + param + data
    cotp = bytes([0x02, 0xF0, 0x80])
    return struct.pack(">BBH", 3, 0, 4 + len(cotp) + len(s7)) + cotp + s7


def szl_param(response=True, dur=0, last=True) -> bytes:
    type_group = 0x84 if response else 0x44  # type 2 = response / 1 = request, group 4
    head = bytes([0x00, 0x01, 0x12, 0x08, 0x12, type_group, 0x01, 0x01])
    return head + bytes([dur, 0x00 if last else 0x01]) + b"\x00\x00"


def szl_data(block: bytes, rc=0xFF) -> bytes:
    return struct.pack(">BBH", rc, 0x09, len(block)) + block


def szl_block(szl_id: int, item_len: int, items: list[bytes]) -> bytes:
    return struct.pack(">HHHH", szl_id, 0, item_len, len(items)) + b"".join(items)


def item_0011(index: int, mlfb: str, ausbg: int, ausbe: int) -> bytes:
    return (
        struct.pack(">H", index) + mlfb.ljust(20).encode() + struct.pack(">HHH", 0xC0, ausbg, ausbe)
    )


def item_001c(index: int, text: str) -> bytes:
    return struct.pack(">H", index) + text.encode().ljust(32, b"\x00")


MODULE_ID = szl_block(
    0x0011,
    28,
    [
        item_0011(0x0001, "6ES7 315-2EH14-0AB0", 0x0003, 0x0001),
        item_0011(0x0007, "", 0x5603, 0x0207),  # 'V' 3 . 2 . 7
    ],
)
COMPONENT_ID = szl_block(
    0x001C,
    34,
    [
        item_001c(0x0001, "Station_1"),
        item_001c(0x0002, "PLC_1"),
        item_001c(0x0007, "CPU 315-2 PN/DP"),
    ],
)


def test_szl_module_identification():
    assert parse_szl(MODULE_ID) == {"order_number": "6ES7 315-2EH14-0AB0", "firmware": "V3.2.7"}


def test_szl_component_identification():
    fields = parse_szl(COMPONENT_ID)
    assert fields["module_type"] == "CPU 315-2 PN/DP"
    assert fields["module_name"] == "PLC_1"


def test_s7_identity_combines_name_order_number_and_firmware():
    fields = {**parse_szl(MODULE_ID), **parse_szl(COMPONENT_ID)}
    assert s7_identity(fields) == {
        "vendor": "Siemens AG",
        "product": "CPU 315-2 PN/DP (6ES7 315-2EH14-0AB0)",
        "firmware": "V3.2.7",
    }


def test_s7_vendor_needs_a_siemens_order_number():
    assert s7_identity({"module_type": "CPU X", "order_number": "VIPA 315-4NE12"})["vendor"] is None


def test_collector_joins_a_response_split_over_two_pdus():
    c = S7SzlCollector()
    first, second = COMPONENT_ID[:50], COMPONENT_ID[50:]
    assert c.feed("plc", "hmi", s7_userdata(szl_param(dur=7, last=False), szl_data(first))) is None
    block = c.feed("plc", "hmi", s7_userdata(szl_param(dur=7, last=True), szl_data(second)))
    assert block == COMPONENT_ID


@pytest.mark.parametrize(
    "payload",
    [
        s7_userdata(szl_param(response=False), szl_data(MODULE_ID)),  # request, not response
        s7_userdata(szl_param(), szl_data(MODULE_ID, rc=0x0A)),  # error return code
        b"\x03\x00\x00\x07\x02\xf0\x80",  # truncated
        b"",
    ],
)
def test_collector_ignores_requests_errors_and_junk(payload):
    assert S7SzlCollector().feed("a", "b", payload) is None


# ── BACnet builders ─────────────────────────────────────────────────────────


def bacnet_ack(prop: int, value: bytes, obj_type=8, npdu=b"\x01\x00", pdu=0x30) -> bytes:
    obj = struct.pack(">I", (obj_type << 22) | 0x3FFFFF)
    apdu = (
        bytes([pdu, 0x01, 0x0C]) + b"\x0c" + obj + bytes([0x19, prop]) + b"\x3e" + value + b"\x3f"
    )
    body = npdu + apdu
    return struct.pack(">BBH", 0x81, 0x0A, 4 + len(body)) + body


def char_string(text: str, charset=0) -> bytes:
    raw = bytes([charset]) + text.encode("utf-16-be" if charset == 4 else "utf-8")
    if len(raw) <= 4:
        return bytes([0x70 | len(raw)]) + raw
    return bytes([0x75, len(raw)]) + raw


def test_bacnet_model_name_in_ucs2():
    assert bacnet_identity(bacnet_ack(70, char_string("MS-NAE4510-2", 4))) == (
        "model_name",
        "MS-NAE4510-2",
    )


def test_bacnet_firmware_in_utf8_and_vendor_identifier():
    assert bacnet_identity(bacnet_ack(44, char_string("5.1.0.4400"))) == (
        "firmware_revision",
        "5.1.0.4400",
    )
    assert bacnet_identity(bacnet_ack(120, b"\x21\x05")) == ("vendor_identifier", 5)


def test_bacnet_npdu_with_source_address_is_skipped_correctly():
    npdu = b"\x01\x08" + b"\x00\x05" + b"\x01" + b"\x07"  # SNET 5, SLEN 1, SADR 7
    assert bacnet_identity(bacnet_ack(121, char_string("ACME"), npdu=npdu)) == (
        "vendor_name",
        "ACME",
    )


@pytest.mark.parametrize(
    "payload",
    [
        bacnet_ack(70, char_string("X1"), obj_type=0),  # analog-input object, not the device
        bacnet_ack(77, char_string("Room 1")),  # object-name is not identity
        bacnet_ack(70, char_string("X1"), pdu=0x00),  # a request, not a ComplexACK
        b"\x81\x0a\x00\x08\x01\x00\x30",  # truncated
        b"\x01\x02",
    ],
)
def test_bacnet_ignores_other_objects_requests_and_junk(payload):
    assert bacnet_identity(payload) is None


def test_bacnet_device_identity():
    fields = {"vendor_name": "JCI", "model_name": "MS-NAE4510-2", "firmware_revision": "5.1.0.4400"}
    assert bacnet_device_identity(fields) == {
        "vendor": "JCI",
        "product": "MS-NAE4510-2",
        "firmware": "5.1.0.4400",
    }


# ── Through the processor ───────────────────────────────────────────────────


def _run(tmp_path, packets):
    path = tmp_path / "t.pcap"
    wrpcap(str(path), packets)
    return {d["ip_address"]: d for d in PcapProcessor().process_file(str(path))["devices"]}


def test_processor_attributes_s7_identity_to_the_responding_plc(tmp_path):
    plc, hmi = "10.0.0.2", "10.0.0.1"
    eth = Ether(src="00:0e:8c:00:00:02", dst="00:0e:8c:00:00:01")
    req = s7_userdata(szl_param(response=False), b"\xff\x09\x00\x04\x00\x11\x00\x00")
    pkts = [
        eth / IP(src=hmi, dst=plc) / TCP(sport=50000, dport=102, flags="PA") / Raw(req),
        eth
        / IP(src=plc, dst=hmi)
        / TCP(sport=102, dport=50000, flags="PA")
        / Raw(s7_userdata(szl_param(), szl_data(MODULE_ID))),
        eth
        / IP(src=plc, dst=hmi)
        / TCP(sport=102, dport=50000, flags="PA")
        / Raw(s7_userdata(szl_param(), szl_data(COMPONENT_ID))),
    ]
    devs = _run(tmp_path, pkts)
    assert devs[plc]["model"] == "CPU 315-2 PN/DP (6ES7 315-2EH14-0AB0)"
    assert devs[plc]["firmware_version"] == "V3.2.7"
    assert devs[plc]["vendor"] == "Siemens AG"
    assert devs[plc]["properties"]["identity"]["evidence"] == [
        "s7comm SZL 0x0011 (packet 2)",
        "s7comm SZL 0x001C (packet 3)",
    ]
    assert devs[hmi]["model"] is None and devs[hmi]["firmware_version"] is None


def test_processor_attributes_bacnet_identity_and_keeps_roles(tmp_path):
    dev, ws = "10.1.1.165", "10.1.1.167"
    eth = Ether(src="00:19:07:00:00:01", dst="3c:a9:f4:00:00:02")
    pkts = [
        eth / IP(src=dev, dst=ws) / UDP(sport=47808, dport=47808) / Raw(bacnet_ack(p, v))
        for p, v in [
            (121, char_string("JCI", 4)),
            (70, char_string("MS-NAE4510-2", 4)),
            (44, char_string("5.1.0.4400", 4)),
        ]
    ]
    devs = _run(tmp_path, pkts)
    assert (devs[dev]["vendor"], devs[dev]["model"], devs[dev]["firmware_version"]) == (
        "JCI",
        "MS-NAE4510-2",
        "5.1.0.4400",
    )
    assert devs[dev]["properties"]["vendor_source"] == "bacnet"
    assert devs[dev]["properties"]["ics_role"] == "server"


def test_processor_reports_no_identity_without_identity_responses(tmp_path):
    plc, hmi = "10.0.0.2", "10.0.0.1"
    eth = Ether(src="00:0e:8c:00:00:02", dst="00:0e:8c:00:00:01")
    modbus = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"
    devs = _run(
        tmp_path,
        [eth / IP(src=hmi, dst=plc) / TCP(sport=40000, dport=502, flags="PA") / Raw(modbus)],
    )
    assert devs[hmi]["model"] is None and "identity" not in devs[hmi]["properties"]
