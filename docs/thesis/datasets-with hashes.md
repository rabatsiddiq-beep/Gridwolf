# Evaluation datasets

## Source
- ITI ICS-Security-Tools, `pcaps/` collection
- Repository: https://github.com/ITI/ICS-Security-Tools
- Pinned commit: 9b826091e7ba3fbdd5997d31e116f29e09cbbb48 (15 Apr 2025)
- Licence: Creative Commons Attribution 4.0 (CC BY 4.0)
- Retrieved: 2 Oct 2026
- File hashes, sizes and contents: see datasets.csv

## Selection criteria
1. Covers the six protocols Gridwolf parses (Modbus, S7comm, EtherNet/IP, DNP3, IEC 104, BACnet)
2. Small enough to label ground truth by hand
3. Includes at least one multi-device, multi-protocol capture (Plant1)
4. Includes captures that disclose device identity (S7 SZL, BACnet), to test product-level matching
5. Includes one Layer-2-only capture (PROFINET-RT) as a control case for passive-discovery limits

## Role of each capture
| Capture | Role in evaluation |
|---|---|
| Combined/Plant1.pcap | Main multi-protocol plant capture: discovery precision/recall |
| ModbusTCP/ModbusTCP.pcap | Modbus slice of Plant1 (subset, not pooled): role classification |
| ModbusTCP/modbus_test_data_part1.pcap | Modbus test/attack traffic; FC17 discloses vendor; FC43 unanswered |
| s7/tia_s300_goOnline.pcapng | S7 identity (CPU model + firmware): product-level matching |
| s7/s7comm_reading_plc_status.pcap | S7 identity (second device type) |
| s7/wincc_s400_production.pcapng | HMI to S7-400 production polling: role classification |
| EthernetIP/EthernetIP-CIP.pcap | EtherNet/IP slice of Plant1 (subset, not pooled) |
| CIP/cip_unclean.pcap | EtherNet/IP with ARP-spoofing man-in-the-middle: precision under hostile noise |
| IEC60870-5-104/090813_diverse.pcap | IEC 104 parsing (single-host simulator; excluded from role metrics) |
| BACnet/bacnet_test.pcap | BACnet roles + identity (vendor, model, firmware) |
| dnp3/full_exchange.pcap | DNP3 roles |
| profinet/PROFINET-RT-DCP/PROFINET-RT.pcap | Control case: Layer-2 traffic invisible to IP-based discovery |

## Ground truth summary (docs/thesis/ground_truth/)
- Method: codebook v1.1 (`codebook.md`), drafts from `gt_draft.py` (tshark), every row verified against cited frames.
- IP ground truth: 87 rows across 11 captures, 83 observable devices (4 receive-only addresses in Plant1).
- **Independent set for aggregate metrics** (Plant1 subsets excluded, R8): **64 devices** in 9 captures.
- Layer-2 / ARP-only devices not visible to IP discovery (`l2_devices.csv`): 11 in PROFINET-RT,
  16 in Plant1, 3 in cip_unclean. Plant1 lists 20 MACs: two switches appear with two port MACs each,
  and two PROFINET names belong to PLCs that are already IP hosts in gt_Plant1.

| Capture | Devices | Classes |
|---|---|---|
| Plant1 | 45 | 29 PLC, 7 HMI/SCADA, 4 OT device (vendor protocol), 1 Historian/DB, 4 IT/Other |
| ModbusTCP (subset) | 14 | 13 PLC, 1 HMI/SCADA |
| EthernetIP-CIP (subset) | 5 | 4 PLC, 1 HMI/SCADA |
| cip_unclean | 4 | 1 PLC, 1 Engineering WS, 2 IT/Other (one is a MITM attacker) |
| modbus_test_data_part1 | 4 | 2 PLC, 1 HMI/SCADA, 1 Engineering WS |
| tia_s300_goOnline | 2 | 1 PLC (CPU 315-2 PN/DP, V3.2.7), 1 Engineering WS |
| s7comm_reading_plc_status | 2 | 1 PLC (IM151-8 PN/DP CPU, V3.2.6), 1 Engineering WS |
| wincc_s400_production | 2 | 1 PLC, 1 HMI/SCADA |
| bacnet_test | 2 | 1 BACnet controller (JCI MS-NAE4510-2, 5.1.0.4400), 1 Engineering WS |
| full_exchange | 2 | 1 RTU, 1 HMI/SCADA |
| 090813_diverse | 1 | 1 Simulator (single host) |

## RQ2 decision (evidence from datasets.csv and ground truth)
Product and firmware are disclosed only in:
- S7 SZL responses (tia_s300_goOnline: CPU 315-2 PN/DP V3.2.7; s7comm_reading_plc_status: IM151-8 PN/DP CPU V3.2.6)
- BACnet readProperty responses (bacnet_test: JCI MS-NAE4510-2, firmware 5.1.0.4400)

Vendor only (no product) is disclosed by Modbus FC17 in modbus_test_data_part1 ("Wingpath Limited").
Modbus FC43 requests in that capture were not answered, so they disclose no identity.
No EtherNet/IP capture contains identity responses.
Layer-2 identity (LLDP/CDP) names switch models and firmware, but those devices have no IP traffic.

Decision: tiered correlation.
- Tier A = product + firmware (S7, BACnet)
- Tier B = vendor only (MAC OUI, Modbus FC17, PROFINET DCP)
- Tier C = no identity

Correlation precision is reported per tier.
ModbusTCP.pcap and EthernetIP-CIP.pcap are subsets of Plant1.pcap and are not pooled with it.

## Security-relevant observations (for the discussion chapter)
- Plant1: remote RDP into the SCADA server (141.81.0.10) from 192.168.113.4 through a WatchGuard firewall.
- cip_unclean: ARP-spoofing man-in-the-middle (192.168.0.47) between the engineering laptop and the PLC.
- modbus_test_data_part1: Modbus FC8 "Force Listen Only Mode" (a known denial-of-service request) and crafted traffic.
