"""
Engineering-action detection (iteration 2b, rule 2).

An engineering workstation is a client that asks a field device for its
identification or diagnostics, transfers program blocks, or changes its operating
mode. An HMI reads and writes process values. Each function below returns a short
label when one request is an engineering action, and None otherwise.

  * S7comm   - Job functions 0x1A-0x1F (block download/upload), 0x28 (PLC control),
               0x29 (PLC stop); userdata requests in the programmer-command (1),
               block-function (3) and security (5) groups; Read SZL (group 4,
               subfunction 1) of the SZL directory (0x00), module identification
               (0x11), component identification (0x1C) or diagnostic buffer (0xA0).
               Reads of status lists such as CPU mode (0x24) or communication
               status (0x31, 0x32) are left out: HMIs read these to show plant state.
  * Modbus   - requests with function 8 (Diagnostics), 17 (Report Server ID) or
               43 (Read Device Identification).
  * EtherNet/IP - ListIdentity requests; CIP reads of the Identity object (class
               0x01); PCCC Diagnostic Status (command 0x06, function 0x03) carried
               by Execute PCCC (service 0x4B, class 0x67).
  * BACnet   - BBMD management (Write-BDT, Read-BDT, Read-FDT, Delete-FDT-Entry);
               DeviceCommunicationControl, ReinitializeDevice, AtomicReadFile and
               AtomicWriteFile; ReadProperty of the Device object's identity
               properties (vendor, model, firmware, software version).

Sources: Siemens System Software for S7-300/400 (SZL lists); Modbus Application
Protocol Specification v1.1b3; ODVA EtherNet/IP and CIP specifications with
Rockwell DF1/PCCC reference (1770-6.5.16); ASHRAE 135 (BACnet) clauses 16 and J.
"""

from __future__ import annotations

import struct
from typing import Optional

from app.engine.identity import BACNET_DEVICE_OBJECT, BACNET_PROPERTIES, _bacnet_apdu, _tag

# ── S7comm ──────────────────────────────────────────────────────────────────

S7_ENGINEERING_JOBS = {
    0x1A: "Request download",
    0x1B: "Download block",
    0x1C: "Download ended",
    0x1D: "Start upload",
    0x1E: "Upload",
    0x1F: "End upload",
    0x28: "PLC control",
    0x29: "PLC stop",
}
S7_ENGINEERING_GROUPS = {1: "programmer command", 3: "block function", 5: "security"}
# SZL partial-list numbers (low byte of the SZL-ID)
S7_ENGINEERING_SZL = {
    0x00: "SZL directory",
    0x11: "module identification",
    0x1C: "component identification",
    0xA0: "diagnostic buffer",
}


def s7_engineering(payload: bytes) -> Optional[str]:
    if len(payload) < 7 or payload[0] != 0x03:
        return None
    s7 = 4 + 1 + payload[4]
    if len(payload) < s7 + 11 or payload[s7] != 0x32:
        return None
    rosctr = payload[s7 + 1]
    if rosctr == 0x01:  # Job request
        name = S7_ENGINEERING_JOBS.get(payload[s7 + 10])
        return f"s7comm {name}" if name else None
    if rosctr != 0x07:  # Userdata
        return None
    param_len, _data_len = struct.unpack_from(">HH", payload, s7 + 6)
    param = payload[s7 + 10 : s7 + 10 + param_len]
    data = payload[s7 + 10 + param_len :]
    if len(param) < 7 or param[5] >> 6 != 1:  # requests only
        return None
    group, subfunc = param[5] & 0x3F, param[6]
    if group in S7_ENGINEERING_GROUPS:
        return f"s7comm {S7_ENGINEERING_GROUPS[group]} (subfunction {subfunc})"
    if group == 4 and subfunc == 1 and len(data) >= 6:
        (szl_id,) = struct.unpack_from(">H", data, 4)
        name = S7_ENGINEERING_SZL.get(szl_id & 0xFF)
        return f"s7comm read SZL 0x{szl_id:04X} ({name})" if name else None
    return None


# ── Modbus ──────────────────────────────────────────────────────────────────

MODBUS_ENGINEERING = {
    8: "Diagnostics",
    17: "Report Server ID",
    43: "Read Device Identification",
}


def modbus_engineering(payload: bytes) -> Optional[str]:
    if len(payload) < 8 or payload[2:4] != b"\x00\x00":
        return None
    name = MODBUS_ENGINEERING.get(payload[7])
    return f"modbus FC{payload[7]} {name}" if name else None


# ── EtherNet/IP and CIP ────────────────────────────────────────────────────


def _cip_requests(payload: bytes):
    """Yield CIP request messages carried in a SendRRData or SendUnitData packet."""
    command = struct.unpack_from("<H", payload, 0)[0]
    if command not in (0x006F, 0x0070) or len(payload) < 32:
        return
    (count,) = struct.unpack_from("<H", payload, 30)
    p = 32
    for _ in range(count):
        if len(payload) < p + 4:
            return
        item_type, length = struct.unpack_from("<HH", payload, p)
        body = payload[p + 4 : p + 4 + length]
        if item_type == 0x00B2:  # unconnected data
            yield body
        elif item_type == 0x00B1 and len(body) > 2:  # connected data: sequence first
            yield body[2:]
        p += 4 + length


def _cip_class(path: bytes) -> Optional[int]:
    i = 0
    while i + 1 < len(path):
        seg = path[i]
        if seg == 0x20:  # 8-bit class
            return path[i + 1]
        if seg == 0x21 and i + 3 < len(path):  # 16-bit class
            return struct.unpack_from("<H", path, i + 2)[0]
        i += 2 if seg in (0x24, 0x30, 0x28) else 4 if seg in (0x25, 0x31, 0x29) else 2
    return None


def enip_engineering(payload: bytes) -> Optional[str]:
    """Engineering action in a client-to-server EtherNet/IP packet."""
    try:
        if len(payload) < 24:
            return None
        command, length = struct.unpack_from("<HH", payload, 0)
        if command == 0x0063 and length == 0:
            return "enip ListIdentity"
        for msg in _cip_requests(payload):
            if len(msg) < 2 or msg[0] & 0x80:  # replies have the top bit set
                continue
            service, words = msg[0], msg[1]
            path = msg[2 : 2 + 2 * words]
            cls = _cip_class(path)
            if cls == 0x01 and service in (0x01, 0x0E):
                return "cip Identity object read"
            if service == 0x4B and cls == 0x67:  # Execute PCCC
                req = msg[2 + 2 * words :]
                if not req:
                    continue
                pccc = req[req[0] :]  # skip the requestor ID (its first byte is its length)
                if len(pccc) >= 5 and pccc[0] == 0x06 and pccc[4] == 0x03:
                    return "pccc Diagnostic Status"
        return None
    except (struct.error, IndexError):
        return None


# ── BACnet ──────────────────────────────────────────────────────────────────

BVLC_MANAGEMENT = {
    0x01: "Write-BDT",
    0x02: "Read-BDT",
    0x06: "Read-FDT",
    0x08: "Delete-FDT-Entry",
}
BACNET_ENGINEERING_SERVICES = {
    6: "AtomicReadFile",
    7: "AtomicWriteFile",
    17: "DeviceCommunicationControl",
    20: "ReinitializeDevice",
}


def bacnet_engineering(payload: bytes) -> Optional[str]:
    try:
        if len(payload) < 4 or payload[0] != 0x81:
            return None
        if payload[1] in BVLC_MANAGEMENT:
            return f"bacnet {BVLC_MANAGEMENT[payload[1]]}"
        apdu = _bacnet_apdu(payload)
        if apdu is None or len(apdu) < 4 or apdu[0] >> 4 != 0:  # Confirmed-Request
            return None
        p = 5 if apdu[0] & 0x08 else 3  # segmented requests carry two more bytes
        service = apdu[p]
        if service in BACNET_ENGINEERING_SERVICES:
            return f"bacnet {BACNET_ENGINEERING_SERVICES[service]}"
        if service != 0x0C:  # ReadProperty
            return None
        number, context, length, q = _tag(apdu, p + 1)
        if not context or number != 0 or length != 4:
            return None
        (obj,) = struct.unpack_from(">I", apdu, q)
        if obj >> 22 != BACNET_DEVICE_OBJECT:
            return None
        number, context, length, q = _tag(apdu, q + 4)
        prop = int.from_bytes(apdu[q : q + length], "big")
        name = BACNET_PROPERTIES.get(prop)
        return f"bacnet ReadProperty {name}" if context and number == 1 and name else None
    except (struct.error, IndexError):
        return None


# ── Dispatcher ──────────────────────────────────────────────────────────────


def engineering_action(protocol: str, payload: bytes, to_server: bool) -> Optional[str]:
    """Label of the engineering action in one packet sent by a client, else None.

    `to_server` says whether the packet travels from the client to the well-known
    server port; Modbus and EtherNet/IP need it because their requests and
    responses share function codes. S7comm and BACnet mark requests themselves.
    """
    try:
        if protocol == "s7comm":
            return s7_engineering(payload)
        if protocol == "bacnet":
            return bacnet_engineering(payload)
        if not to_server:
            return None
        if protocol == "modbus":
            return modbus_engineering(payload)
        if protocol == "enip":
            return enip_engineering(payload)
    except (struct.error, IndexError):
        return None
    return None
