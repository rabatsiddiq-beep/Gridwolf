"""
Device identity extraction from industrial protocol responses (iteration 2a).

Rule (docs/thesis/iteration2_rules.md, rule 1): product and firmware are read only
from responses that a device sends about itself:

  * S7comm  - "Read SZL" userdata responses (CPU functions, subfunction 1):
              SZL 0x001C / 0x011C  component identification -> module type name
              SZL 0x0011 / 0x0111  module identification    -> order number (MLFB),
                                                                firmware (index 0x0007)
  * BACnet  - ComplexACK to ReadProperty on the Device object:
              vendor-name (121), vendor-identifier (120), model-name (70),
              firmware-revision (44), application-software-version (12)

Nothing is inferred from ports, MAC addresses or device types. Each value is kept
with the packet number it came from, so it can be checked in Wireshark.

References: Siemens "System Software for S7-300/400 System and Standard Functions"
(SZL list descriptions); ASHRAE 135 (BACnet) clauses 12.11 (Device object) and
20.2 (encoding of tags).
"""

from __future__ import annotations

import struct
from typing import Optional

# ── S7comm ──────────────────────────────────────────────────────────────────

S7_USERDATA = 0x07
S7_GROUP_CPU_FUNCTIONS = 0x04
S7_SUBFUNC_READ_SZL = 0x01
S7_TYPE_RESPONSE = 0x02

SZL_COMPONENT_ID = (0x001C, 0x011C)  # component identification
SZL_MODULE_ID = (0x0011, 0x0111)  # module identification

# SZL 0x001C item indexes
SZL1C_FIELDS = {
    0x0001: "station_name",
    0x0002: "module_name",
    0x0005: "serial_number",
    0x0007: "module_type",
}

# Order-number prefixes used by Siemens (SIMATIC 6ES7, SIPLUS 6AG1)
SIEMENS_ORDER_PREFIXES = ("6ES7", "6AG1")


def _s7_userdata(payload: bytes) -> Optional[dict]:
    """Split a TPKT/COTP/S7comm userdata PDU into its parameter and data fields."""
    if len(payload) < 7 or payload[0] != 0x03:
        return None
    s7 = 4 + 1 + payload[4]  # TPKT (4) + COTP length byte + COTP header
    if len(payload) < s7 + 10 or payload[s7] != 0x32 or payload[s7 + 1] != S7_USERDATA:
        return None
    param_len, data_len = struct.unpack_from(">HH", payload, s7 + 6)
    p = s7 + 10
    param = payload[p : p + param_len]
    data = payload[p + param_len : p + param_len + data_len]
    if len(param) < 8 or len(param) != param_len:
        return None
    return {"param": param, "data": data}


class S7SzlCollector:
    """Collect S7 'Read SZL' responses, joining responses split into several PDUs."""

    def __init__(self) -> None:
        self._parts: dict[tuple, bytearray] = {}

    def feed(self, src_ip: str, dst_ip: str, payload: bytes) -> Optional[bytes]:
        """Return the complete SZL data block when the last part arrives, else None."""
        ud = _s7_userdata(payload)
        if ud is None:
            return None
        param, data = ud["param"], ud["data"]
        msg_type, group, subfunc = param[5] >> 6, param[5] & 0x3F, param[6]
        if (
            msg_type != S7_TYPE_RESPONSE
            or group != S7_GROUP_CPU_FUNCTIONS
            or subfunc != S7_SUBFUNC_READ_SZL
        ):
            return None
        if len(data) < 4 or data[0] != 0xFF:  # return code 0xFF = success
            return None
        (length,) = struct.unpack_from(">H", data, 2)
        chunk = bytes(data[4 : 4 + length])
        data_unit_ref = param[8] if len(param) >= 12 else 0
        more = len(param) >= 12 and param[9] != 0x00
        key = (src_ip, dst_ip, data_unit_ref)
        if more:
            self._parts.setdefault(key, bytearray()).extend(chunk)
            return None
        return bytes(self._parts.pop(key, bytearray())) + chunk


def _s7_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("latin-1", errors="replace").strip()


def parse_szl(block: bytes) -> dict:
    """Decode an SZL data block (SZL-ID, index, item length, count, items)."""
    out: dict = {}
    if len(block) < 8:
        return out
    szl_id, _index, item_len, count = struct.unpack_from(">HHHH", block, 0)
    items = block[8:]
    for i in range(count):
        item = items[i * item_len : (i + 1) * item_len]
        if len(item) < item_len or item_len < 2:
            break
        (idx,) = struct.unpack_from(">H", item, 0)
        if szl_id in SZL_COMPONENT_ID and item_len >= 34:
            field = SZL1C_FIELDS.get(idx)
            value = _s7_string(item[2:34])
            if field and value:
                out[field] = value
        elif szl_id in SZL_MODULE_ID and item_len >= 28:
            mlfb = _s7_string(item[2:22])
            ausbg, ausbe = struct.unpack_from(">HH", item, 24)
            if idx == 0x0001 and mlfb:
                out["order_number"] = mlfb
            elif idx == 0x0007 and (ausbg >> 8) == ord("V"):
                out["firmware"] = f"V{ausbg & 0xFF}.{ausbe >> 8}.{ausbe & 0xFF}"
    return out


def s7_identity(fields: dict) -> dict:
    """Combine collected SZL fields into vendor, product and firmware."""
    module, order = fields.get("module_type"), fields.get("order_number")
    if module and order:
        product = f"{module} ({order})"
    else:
        product = module or order
    vendor = None
    if order and order.replace(" ", "").upper().startswith(SIEMENS_ORDER_PREFIXES):
        vendor = "Siemens AG"
    return {"vendor": vendor, "product": product, "firmware": fields.get("firmware")}


# ── BACnet ──────────────────────────────────────────────────────────────────

BACNET_COMPLEX_ACK = 0x03
BACNET_READ_PROPERTY = 0x0C
BACNET_DEVICE_OBJECT = 8

BACNET_PROPERTIES = {
    121: "vendor_name",
    120: "vendor_identifier",
    70: "model_name",
    44: "firmware_revision",
    12: "application_software_version",
}

BACNET_CHARSETS = {0: "utf-8", 3: "utf-32-be", 4: "utf-16-be", 5: "latin-1"}


def _bacnet_apdu(payload: bytes) -> Optional[bytes]:
    """Return the APDU of a BACnet/IP packet, skipping the BVLC and NPDU headers."""
    if len(payload) < 6 or payload[0] != 0x81:
        return None
    off = 4
    if payload[1] == 0x04:  # Forwarded-NPDU carries the original address (6 bytes)
        off += 6
    if len(payload) < off + 2 or payload[off] != 0x01:
        return None
    ctrl = payload[off + 1]
    off += 2
    if ctrl & 0x80:  # network-layer message, no APDU
        return None
    if ctrl & 0x20:  # destination specifier: DNET (2), DLEN (1), DADR
        off += 3 + payload[off + 2]
    if ctrl & 0x08:  # source specifier: SNET (2), SLEN (1), SADR
        off += 3 + payload[off + 2]
    if ctrl & 0x20:  # hop count
        off += 1
    return payload[off:] if len(payload) > off else None


def _tag(apdu: bytes, p: int) -> tuple[int, bool, int, int]:
    """Decode a BACnet tag at p: (tag number, is context tag, length, value offset)."""
    b = apdu[p]
    number, context, lvt = b >> 4, bool(b & 0x08), b & 0x07
    p += 1
    if number == 0x0F:  # extended tag number
        number = apdu[p]
        p += 1
    if lvt == 5:  # extended length
        lvt = apdu[p]
        p += 1
        if lvt == 254:
            (lvt,) = struct.unpack_from(">H", apdu, p)
            p += 2
        elif lvt == 255:
            (lvt,) = struct.unpack_from(">I", apdu, p)
            p += 4
    return number, context, lvt, p


def bacnet_identity(payload: bytes) -> Optional[tuple[str, object]]:
    """Return (property, value) from a ReadProperty ComplexACK on the Device object."""
    try:
        apdu = _bacnet_apdu(payload)
        if apdu is None or len(apdu) < 4:
            return None
        if apdu[0] >> 4 != BACNET_COMPLEX_ACK or apdu[0] & 0x08:  # not segmented
            return None
        if apdu[2] != BACNET_READ_PROPERTY:
            return None
        p = 3
        number, context, length, p = _tag(apdu, p)  # [0] object identifier
        if not context or number != 0 or length != 4:
            return None
        (obj,) = struct.unpack_from(">I", apdu, p)
        if obj >> 22 != BACNET_DEVICE_OBJECT:
            return None
        p += 4
        number, context, length, p = _tag(apdu, p)  # [1] property identifier
        if not context or number != 1:
            return None
        prop = int.from_bytes(apdu[p : p + length], "big")
        p += length
        name = BACNET_PROPERTIES.get(prop)
        if name is None:
            return None
        if apdu[p] >> 4 == 2 and apdu[p] & 0x08 and apdu[p] & 0x07 != 6:  # [2] index
            _n, _c, length, p = _tag(apdu, p)
            p += length
        if apdu[p] != 0x3E:  # opening tag [3]
            return None
        number, context, length, p = _tag(apdu, p + 1)
        value = apdu[p : p + length]
        if context or len(value) != length:
            return None
        if number == 7 and length >= 1:  # CharacterString
            charset = BACNET_CHARSETS.get(value[0])
            if charset is None:
                return None
            text = value[1:].decode(charset, errors="replace").strip("\x00 ").strip()
            return (name, text) if text else None
        if number == 2:  # Unsigned
            return name, int.from_bytes(value, "big")
        return None
    except (IndexError, struct.error):
        return None


def bacnet_device_identity(fields: dict) -> dict:
    """Combine collected BACnet Device properties into vendor, product and firmware."""
    vendor = fields.get("vendor_name")
    return {
        "vendor": vendor,
        "product": fields.get("model_name"),
        "firmware": fields.get("firmware_revision") or fields.get("application_software_version"),
    }
