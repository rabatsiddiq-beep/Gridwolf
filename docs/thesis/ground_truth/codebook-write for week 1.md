# Ground-truth labelling codebook

Version 1.0, 3 Oct 2026. These rules were fixed before any capture was labelled
and are applied to every capture in the same way.

## Method
- Labels are produced with Wireshark/tshark 4.x dissectors, which act as an
  independent reference implementation. Gridwolf is never run on a capture
  before its ground truth is finished (blind labelling).
- `gt_draft.py` produces a machine draft (`draft_*.csv`). Every row is then checked
  by hand in Wireshark and saved as the verified ground truth (`gt_*.csv`).
  Both files are kept as an audit trail.

## R1 – What counts as a device
- A device is a unicast IPv4 address that **sends at least one packet** in the capture
  (an "observable device").
- Excluded: broadcast (x.x.x.255, 255.255.255.255), multicast (224.0.0.0/4), 0.0.0.0.
- Receive-only addresses are listed with `is_device = N` and a note.
- Layer-2-only devices (no IP) are recorded separately in `l2_devices.csv`.

## R2 – Role
- **server**: accepts connections on, or answers from, a well-known ICS port
  (502 Modbus, 102 S7comm, 44818/2222 EtherNet/IP, 20000 DNP3, 2404 IEC 104, 47808 BACnet).
- **client**: opens connections to, or sends requests to, such a port.
- For TCP, the SYN / SYN-ACK direction decides. For UDP and BACnet (47808 to 47808),
  the side that answers requests (e.g. BACnet Complex-ACK) is the server.
- **both**: does both. Single-host simulators are labelled `both` and excluded
  from role-classification metrics.

## R3 – Device class
| Evidence | Class |
|---|---|
| Server on Modbus / S7comm / EtherNet/IP | PLC |
| Server on DNP3 / IEC 104 | RTU |
| Server on BACnet | BACnet controller |
| Client that polls or writes process values | HMI/SCADA |
| Client that does engineering actions (go online, upload/download blocks, SZL/diagnostic reads, firmware) | Engineering workstation |
| No ICS protocol | IT/Other |
| Same host is both ends of an ICS session | Simulator (single host) |

## R4 – Vendor
- Taken from the MAC OUI, as resolved by Wireshark, **only if** that MAC belongs to one IP.
- If one MAC carries several IPs, the MAC belongs to a router or gateway, so the vendor is unknown.
- If the OUI is a network vendor (e.g. Cisco) but a protocol field names the device
  vendor, the protocol field wins. Note "MAC is router".

## R5 – Product and firmware
- Recorded **only** from protocol fields that state them, never guessed:
  - S7comm SZL 0x001C (module type name) and 0x0011 (order number, firmware at index 0x0007)
  - BACnet readProperty responses (vendor-name, model-name, firmware-revision)
  - Modbus FC43 **responses** (a request with no answer discloses nothing)
  - Modbus FC17 Report Slave ID responses (vendor string)
  - CIP Identity object, PROFINET DCP
- S7 firmware decoding: SZL 0x0011 index 0x0007, Ausbg high byte = 'V' (0x56),
  low byte = major; Ausbe high byte = minor, low byte = patch.
  Example: Ausbg 22019 (0x5603) + Ausbe 519 (0x0207) = V3.2.7.

## R6 – Confidence
- **H**: role and class come from an explicit protocol transaction.
- **M**: inferred from ports or traffic pattern only.
- **L**: little traffic; best judgement.

## R7 – Evidence
- Every verified row cites at least one frame number or display filter that supports it,
  e.g. `frame 4 (Complex-ACK readProperty)` or `ip.src==10.0.0.3 && tcp.flags==0x12`.

## R8 – Overlapping captures
- `ModbusTCP.pcap` and `EthernetIP-CIP.pcap` contain the same 141.81.0.x hosts as `Plant1.pcap`.
  They are labelled consistently with Plant1 and reported as per-protocol slices.
  They are **not** pooled with Plant1 in the aggregate metrics, to avoid double counting.
