   # Iteration 2 rules
   Each rule is written before it is implemented or run on the captures,
   with the protocol documentation it comes from.

   ## Rule 1 – Device identity (written <today's date>)
   Product and firmware are taken only from responses a device sends about itself:
   - S7comm "Read SZL" responses: SZL 0x001C index 7 (module type name);
     SZL 0x0011 index 1 (order number) and index 7 (firmware, from Ausbg/Ausbe).
     Source: Siemens, System Software for S7-300/400, System Status Lists.
   - BACnet ReadProperty Complex-ACK on the Device object: vendor-name (121),
     model-name (70), firmware-revision (44), application-software-version (12).
     Source: ASHRAE 135, Device object.
   - A vendor stated by the device outranks the MAC OUI vendor. S7 vendor is
     "Siemens" only when the order number starts with 6ES7 or 6AG1.
   - Nothing is inferred from ports, MAC addresses or device type.
   - Not included: Modbus FC43 (never answered in the corpus) and FC17
     (free-text vendor string only).
   Expected effect: product and firmware only where such responses exist;
   discovery, role and class results unchanged.