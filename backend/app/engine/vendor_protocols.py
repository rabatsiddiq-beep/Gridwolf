"""
Documented vendor OT protocols outside the six evaluated protocols (iteration 2b, rule 3).

These protocols do not take part in the server/client roles of the six industrial
protocols (codebook R2). They are used only to type hosts that would otherwise stay
unknown:

  * SICK CoLa (TCP 2111) - command language of SICK sensors, scanners and readers.
    Port 2111 is also registered to other services, so the payload must be a CoLa A
    telegram (STX 0x02, 's' + command, ETX 0x03) or a CoLa B frame (four STX bytes).
    The endpoint on port 2111 is the SICK device -> OT device, Purdue level 1.
  * Wonderware / AVEVA SuiteLink (TCP 5413, IANA "wwiotalk") - links InTouch HMI
    clients to I/O and SCADA servers. A client is an HMI; a server is a SCADA server.

A generic port such as TCP 8000 is never used to type a host.

Sources: SICK "Telegram Listing" (CoLa A / CoLa B); AVEVA (Wonderware) SuiteLink
technical note; IANA service name and port number registry (2111, 5413).
"""

from __future__ import annotations

from typing import Optional

COLA_PORT = 2111
SUITELINK_PORT = 5413

COLA_COMMANDS = (b"sRN", b"sWN", b"sMN", b"sEN", b"sRI", b"sRA", b"sWA", b"sAN", b"sEA", b"sMA",
                 b"sAI", b"sFA", b"sSN")  # fmt: skip

# protocol -> (device type when server, device type when client, Purdue level)
VENDOR_DEVICE_TYPE = {
    "sick-cola": ("OT_DEVICE", None, "L1"),
    "suitelink": ("SCADA_SERVER", "HMI", "L2"),
}


def is_cola(payload: bytes) -> bool:
    if payload.startswith(b"\x02\x02\x02\x02"):  # CoLa B
        return len(payload) >= 9
    return (
        len(payload) >= 5
        and payload[0] == 0x02
        and payload.rstrip(b"\x00")[-1:] == b"\x03"
        and payload[1:4] in COLA_COMMANDS
    )


def vendor_endpoints(
    sport: int, dport: int, src_ip: str, dst_ip: str, payload: bytes
) -> Optional[tuple[str, str, str]]:
    """Return (protocol, server_ip, client_ip) for a vendor-protocol TCP packet."""
    if not payload:
        return None
    if COLA_PORT in (sport, dport) and is_cola(payload):
        server_is_src = sport == COLA_PORT
        protocol = "sick-cola"
    elif SUITELINK_PORT in (sport, dport):
        server_is_src = sport == SUITELINK_PORT
        protocol = "suitelink"
    else:
        return None
    if server_is_src:
        return protocol, src_ip, dst_ip
    return protocol, dst_ip, src_ip
