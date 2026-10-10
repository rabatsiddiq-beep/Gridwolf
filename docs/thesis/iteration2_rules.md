# Iteration 2 rules

Each rule is written before it is implemented or run on the captures,
with the protocol documentation it comes from.

## Rule 1 – Device identity (written <today's date>)

Product and firmware are taken only from responses a device sends about itself:

* S7comm "Read SZL" responses: SZL 0x001C index 7 (module type name);
SZL 0x0011 index 1 (order number) and index 7 (firmware, from Ausbg/Ausbe).
Source: Siemens, System Software for S7-300/400, System Status Lists.
* BACnet ReadProperty Complex-ACK on the Device object: vendor-name (121),
model-name (70), firmware-revision (44), application-software-version (12).
Source: ASHRAE 135, Device object.
* A vendor stated by the device outranks the MAC OUI vendor. S7 vendor is
"Siemens" only when the order number starts with 6ES7 or 6AG1.
* Nothing is inferred from ports, MAC addresses or device type.
* Not included: Modbus FC43 (never answered in the corpus) and FC17
(free-text vendor string only).
Expected effect: product and firmware only where such responses exist;
discovery, role and class results unchanged.





\## Rule 2 – Engineering workstation (written <today's date>)

A client is an engineering workstation if it asks a device for its identity or

diagnostics, transfers program blocks, or changes its operating mode. An HMI

reads and writes process values.

\- S7comm: block download/upload (job functions 0x1A–0x1F), PLC control (0x28),

&#x20; PLC stop (0x29); userdata programmer commands, block functions (e.g. list

&#x20; blocks) and security; Read SZL of the SZL directory (0x00), module or

&#x20; component identification (0x11, 0x1C) or diagnostic buffer (0xA0).

&#x20; Not included: CPU-mode and communication-status lists (0x24, 0x31, 0x32),

&#x20; which HMIs read to display plant state.

&#x20; Source: Siemens, System Software for S7-300/400, System Status Lists.

\- Modbus: function 8 (Diagnostics), 17 (Report Server ID), 43 (Read Device

&#x20; Identification). Source: Modbus Application Protocol Specification v1.1b3.

\- EtherNet/IP: ListIdentity; reads of the CIP Identity object; PCCC Diagnostic

&#x20; Status (command 0x06, function 0x03). Sources: ODVA CIP specification;

&#x20; Rockwell DF1 protocol reference (1770-6.5.16).

\- BACnet: BBMD table management (Read/Write-BDT, Read-FDT, Delete-FDT-Entry);

&#x20; DeviceCommunicationControl, ReinitializeDevice, AtomicRead/WriteFile;

&#x20; ReadProperty of the Device object's vendor, model and firmware.

&#x20; Source: ASHRAE 135, clauses 16 and J.

A device that serves an industrial protocol keeps its server type.



\## Rule 3 – Documented vendor OT protocols (written <today's date>)

Used only for hosts with no role in the six protocols; not counted as roles.

\- SICK CoLa, TCP 2111: the endpoint on 2111 is a SICK field device -> OT device,

&#x20; Purdue level 1. Port 2111 is also registered to other services, so the payload

&#x20; must be a CoLa telegram (STX, 's' command, ETX). Source: SICK Telegram Listing.

\- Wonderware/AVEVA SuiteLink, TCP 5413 (IANA "wwiotalk"): a client is an HMI

&#x20; (InTouch operator station); a server is a SCADA server.

&#x20; Source: AVEVA SuiteLink technical note; IANA port registry.

\- Generic ports (e.g. TCP 8000) are never used to type a host.

Expected effect: engineering workstations and SICK devices typed; operator

stations typed as HMI; discovery, roles and identity unchanged.



\## Rule 4 – Urgency tiers on correlated CVEs (written <today's date>)

Each matched CVE gets the urgency tier of Table 4.3 (first matching rule applies):

\- Act now: KEV-listed; or CVSS >= 9.0 with network (or unstated) attack vector;

&#x20; or EPSS > 0.10

\- Plan patch: CVSS >= 7.0 with a fix available; or CVSS >= 8.0

\- Monitor: CVSS >= 4.0

\- Low risk: everything else

"Fix available" = the matched NVD CPE entry states a first fixed version

(versionEndExcluding). The same code serves the advisory feed and correlation.

A CPE whose version is "-" (not applicable, e.g. hardware) cannot be checked

against firmware, so its version check is "unknown", not "affected".

Ranking within a device is unchanged: KEV, then EPSS, then CVSS.

Source: Table 4.3 (fixed in Week 1); NVD CPE match criteria documentation.

