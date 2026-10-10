"""Regression tests for device roles and device discovery in the PCAP processor.

These pin the behaviour fixed for the thesis evaluation:
  * the endpoint on the well-known ICS port is the server (PLC/RTU), the other is the client
  * only hosts that send traffic are devices; broadcast/multicast addresses are never devices
  * an unanswered connection attempt does not give a host a role
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402

from app.engine.pcap_processor import PcapProcessor, is_device_address  # noqa: E402

HMI, PLC = "10.0.0.10", "10.0.0.20"
HMI_MAC, PLC_MAC = "00:0c:29:11:11:11", "00:00:bc:22:22:22"


def _run(tmp_path, packets) -> dict:
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), packets)
    result = PcapProcessor().process_file(str(path))
    return {d["ip_address"]: d for d in result["devices"]}


def _modbus_poll(n: int = 3) -> list:
    pkts = []
    for i in range(n):
        req = i.to_bytes(2, "big") + b"\x00\x00\x00\x06\x01\x03\x00\x00\x00\x02"
        rsp = i.to_bytes(2, "big") + b"\x00\x00\x00\x07\x01\x03\x04\x00\x0a\x00\x0b"
        pkts.append(
            Ether(src=HMI_MAC, dst=PLC_MAC)
            / IP(src=HMI, dst=PLC)
            / TCP(sport=50000, dport=502, flags="PA")
            / Raw(req)
        )
        pkts.append(
            Ether(src=PLC_MAC, dst=HMI_MAC)
            / IP(src=PLC, dst=HMI)
            / TCP(sport=502, dport=50000, flags="PA")
            / Raw(rsp)
        )
    return pkts


def test_modbus_plc_is_server_and_hmi_is_client(tmp_path):
    devices = _run(tmp_path, _modbus_poll())
    assert devices[PLC]["device_type"] == "PLC"
    assert devices[PLC]["properties"]["ics_role"] == "server"
    assert 502 in devices[PLC]["open_ports"]
    assert devices[HMI]["device_type"] == "HMI"
    assert devices[HMI]["properties"]["ics_role"] == "client"


def test_s7_plc_is_server(tmp_path):
    job = b"\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00\x00\x00\x01\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0"
    ack = b"\x03\x00\x00\x1b\x02\xf0\x80\x32\x03\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0"
    pkts = [
        IP(src=HMI, dst=PLC) / TCP(sport=50001, dport=102, flags="PA") / Raw(job),
        IP(src=PLC, dst=HMI) / TCP(sport=102, dport=50001, flags="PA") / Raw(ack),
    ]
    devices = _run(tmp_path, pkts)
    assert devices[PLC]["device_type"] == "PLC"
    assert devices[PLC]["properties"]["ics_role"] == "server"
    assert devices[HMI]["properties"]["ics_role"] == "client"


def test_unanswered_syn_does_not_change_roles(tmp_path):
    # PLC tries (and fails) to open a connection to port 102 on the HMI
    syn = (
        Ether(src=PLC_MAC, dst=HMI_MAC)
        / IP(src=PLC, dst=HMI)
        / TCP(sport=49196, dport=102, flags="S")
    )
    devices = _run(tmp_path, [syn] + _modbus_poll())
    assert devices[PLC]["properties"]["ics_role"] == "server"
    assert devices[HMI]["properties"]["ics_role"] == "client"


def test_receive_only_address_is_not_a_device(tmp_path):
    ghost = "10.0.0.99"
    syn = Ether(src=HMI_MAC) / IP(src=HMI, dst=ghost) / TCP(sport=50002, dport=502, flags="S")
    devices = _run(tmp_path, _modbus_poll() + [syn])
    assert ghost not in devices
    assert set(devices) == {HMI, PLC}


def test_broadcast_and_multicast_are_not_devices(tmp_path):
    pkts = _modbus_poll() + [
        Ether(src=HMI_MAC)
        / IP(src=HMI, dst="10.0.0.255")
        / UDP(sport=137, dport=137)
        / Raw(b"x" * 10),
        Ether(src=HMI_MAC)
        / IP(src=HMI, dst="224.0.0.252")
        / UDP(sport=5355, dport=5355)
        / Raw(b"x" * 10),
    ]
    devices = _run(tmp_path, pkts)
    assert "10.0.0.255" not in devices
    assert "224.0.0.252" not in devices


def test_bacnet_same_port_uses_message_direction(tmp_path):
    client, server = "10.1.1.167", "10.1.1.165"
    bvlc_req = b"\x81\x0a\x00\x11\x01\x04\x02\x05\x01\x0c\x0c\x02\x3f\xff\xff\x19\x4b"
    bvlc_ack = b"\x81\x0a\x00\x14\x01\x00\x30\x01\x0c\x0c\x02\x3f\xff\xff\x19\x4b\x3e\xc4\x02\x00\x01\xf4\x3f"
    pkts = [
        IP(src=client, dst=server) / UDP(sport=47808, dport=47808) / Raw(bvlc_req),
        IP(src=server, dst=client) / UDP(sport=47808, dport=47808) / Raw(bvlc_ack),
    ]
    devices = _run(tmp_path, pkts)
    assert devices[server]["properties"]["ics_role"] == "server"
    assert devices[client]["properties"]["ics_role"] == "client"


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("10.0.0.5", True),
        ("10.0.0.255", False),
        ("255.255.255.255", False),
        ("224.0.0.22", False),
        ("239.255.255.250", False),
        ("0.0.0.0", False),
        ("not-an-ip", False),
    ],
)
def test_is_device_address(ip, expected):
    assert is_device_address(ip) is expected


def test_one_failing_packet_is_skipped_not_fatal(tmp_path, monkeypatch):
    """A packet whose analysis raises is counted and skipped; the rest is analysed."""
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    from app.engine import pcap_processor as pp

    real = pp.parse_modbus
    calls = {"n": 0}

    def flaky(payload, src, dst, ts):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("boom")
        return real(payload, src, dst, ts)

    monkeypatch.setattr(pp, "parse_modbus", flaky)
    monkeypatch.setattr(
        pp.PcapProcessor,
        "_dissect_protocol",
        lambda self, proto, s, d, sp, dp, pl, ts: flaky(pl, s, d, ts),
    )
    req = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"
    pkts = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=502, flags="PA")
        / Raw(req)
        for _ in range(3)
    ]
    path = tmp_path / "t.pcap"
    wrpcap(str(path), pkts)
    res = pp.PcapProcessor().process_file(str(path))
    assert res["packet_count"] == 3
    assert res["packet_errors"] == 1
    assert {d["ip_address"] for d in res["devices"]} == {"10.0.0.1"}
