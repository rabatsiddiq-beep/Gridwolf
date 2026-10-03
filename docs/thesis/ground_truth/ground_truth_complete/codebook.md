# Ground-truth labelling codebook

Version 1.1, 4 Oct 2026. Version 1.0 (3 Oct 2026) was fixed before any capture was labelled.
The v1.1 amendments are listed at the end, with the reason for each. They were needed for
situations found in the large captures, and they were applied to all captures.

## Method
- Labels are produced with Wireshark/tshark 4.x dissectors, which act as an
  independent reference implementation. Gridwolf is never run on a capture
  before its ground truth is finished (blind labelling).
- `gt_draft.py` produces a machine draft (`draft_*.csv`). Every row is then checked
  against the cited frames and saved as the verified ground truth (`gt_*.csv`).
  Both files are kept as an audit trail.

## R1 – What counts as a device
- A device is a unicast IPv4 address that **sends at least one IP packet** in the capture
  (an "observable device").
- Excluded: broadcast (x.x.x.255, 255.255.255.255), multicast (224.0.0.0/4), 0.0.0.0.
- Receive-only addresses are listed with `is_device = N` and a note.
- Devices that send no IP packets (Layer-2-only or ARP-only) are recorded separately in
  `l2_devices.csv`. They are not counted in the IP ground truth, but they are used to report
  what IP-based passive discovery cannot see.

## R2 – Role (for the six evaluated ICS protocols)
- **server**: accepts connections on, or answers from, a well-known ICS port
  (502 Modbus, 102 S7comm, 44818/2222 EtherNet/IP, 20000 DNP3, 2404 IEC 104, 47808 BACnet).
- **client**: opens connections to, or sends requests to, such a port.
- For TCP, the SYN / SYN-ACK direction decides. If the session started before the capture,
  the side sending from the well-known port is the server. For BACnet (47808 to 47808),
  the side that answers requests (e.g. Complex-ACK) is the server.
- **both**: does both. Single-host simulators are labelled `both` and excluded
  from role-classification metrics.
- **none-ICS**: uses none of the six protocols, even if it speaks a vendor protocol.

## R3 – Device class
| Evidence | Class |
|---|---|
| Server on Modbus / S7comm / EtherNet/IP | PLC |
| Server on DNP3 / IEC 104 | RTU |
| Server on BACnet | BACnet controller |
| Client that polls or writes process values, or operator station fed by a SCADA server | HMI/SCADA |
| Client that does engineering actions (go online, block upload/download, SZL/diagnostic reads, firmware) | Engineering workstation |
| Server on a vendor-specific industrial port not in R2 (e.g. SICK 2111, Logopak 8000) | OT device (vendor protocol) *(v1.1)* |
| Database or historian serving the SCADA system (e.g. SQL Server 1433) | Historian/DB server *(v1.1)* |
| No industrial role | IT/Other |
| Same host is both ends of an ICS session | Simulator (single host) |

## R4 – Vendor
- Taken from the MAC OUI, as resolved by Wireshark, **only if** that MAC belongs to that IP alone.
- If one MAC carries several IPs because it is a router or gateway, the vendor is unknown.
- If the OUI is a network or security vendor (e.g. Cisco, WatchGuard) and the traffic is routed,
  the vendor is unknown, unless a protocol field names the device vendor. In that case the
  protocol field wins.
- *(v1.1)* If a MAC is shared because of **ARP spoofing** (one host's ARP replies claim other IPs and
  it forwards their traffic), each victim's vendor is taken from its own MAC (its own ARP replies and
  original frames). The spoofing host is labelled separately.

## R5 – Product and firmware
- Recorded **only** from protocol fields that state them, never guessed:
  - S7comm SZL 0x001C (module type name) and 0x0011 (order number, firmware at index 0x0007)
  - BACnet readProperty responses (vendor-name, model-name, firmware-revision)
  - Modbus FC43 **responses** (a request with no answer discloses nothing)
  - Modbus FC17 Report Slave ID responses (vendor string)
  - CIP Identity object, PROFINET DCP
  - *(v1.1)* LLDP / CDP system descriptions (for `l2_devices.csv`)
- S7 firmware decoding: SZL 0x0011 index 0x0007, Ausbg high byte = 'V' (0x56),
  low byte = major; Ausbe high byte = minor, low byte = patch.
  Example: Ausbg 22019 (0x5603) + Ausbe 519 (0x0207) = V3.2.7.

## R6 – Confidence
- **H**: role and class come from an explicit protocol transaction.
- **M**: inferred from ports or traffic pattern only.
- **L**: little traffic; best judgement.

## R7 – Evidence
- Every verified row cites at least one frame number or display filter that supports it,
  e.g. `f4 Complex-ACK readProperty`.

## R8 – Overlapping captures
- `ModbusTCP.pcap` and `EthernetIP-CIP.pcap` contain the same 141.81.0.x hosts as `Plant1.pcap`.
  They are labelled consistently with Plant1 and reported as per-protocol slices.
  They are **not** pooled with Plant1 in the aggregate metrics, to avoid double counting.

## Amendments in v1.1 (4 Oct 2026)
| Rule | Change | Reason |
|---|---|---|
| R1 | ARP-only devices go to `l2_devices.csv` together with the IP they claim | Plant1 and cip_unclean contain devices that announce an IP via ARP but never send IP packets |
| R2 | Added the `none-ICS` value and the session-already-started case | Most Plant1 sessions began before the capture (no SYN) |
| R3 | Added the classes "OT device (vendor protocol)" and "Historian/DB server" | Plant1 has SICK, Logopak and SQL Server hosts that are OT but use none of the six protocols |
| R4 | Added the ARP-spoofing case | cip_unclean contains a man-in-the-middle host |
| R5 | Added LLDP / CDP as identity sources for Layer-2 devices | Plant1 and cip_unclean switches disclose model and firmware via LLDP/CDP |
