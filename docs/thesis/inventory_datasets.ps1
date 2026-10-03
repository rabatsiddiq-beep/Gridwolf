# Records provenance + contents of each evaluation capture (thesis, Week 1)
$env:Path += ";C:\Program Files\Wireshark"
$root = "C:\thesisgrid"
$base = "$root\datasets\ICS-Security-Tools\pcaps"
$out  = "$root\Gridwolf\docs\thesis\datasets.csv"
$files = @(
  "Combined\Plant1.pcap",
  "ModbusTCP\ModbusTCP.pcap",
  "ModbusTCP\modbus_test_data_part1.pcap",
  "s7\tia_s300_goOnline.pcapng",
  "s7\s7comm_reading_plc_status.pcap",
  "s7\wincc_s400_production.pcapng",
  "EthernetIP\EthernetIP-CIP.pcap",
  "CIP\cip_unclean.pcap",
  "IEC60870-5-104\090813_diverse.pcap",
  "BACnet\bacnet_test.pcap",
  "dnp3\full_exchange.pcap",
  "profinet\PROFINET-RT-DCP\PROFINET-RT.pcap"
)
function Count($p, $filter) { (tshark -r $p -Y $filter 2>$null | Measure-Object -Line).Lines }

$rows = foreach ($f in $files) {
  $p = Join-Path $base $f
  [pscustomobject]@{
    File         = $f
    Bytes        = (Get-Item $p).Length
    Packets      = (tshark -r $p 2>$null | Measure-Object -Line).Lines
    IPs          = (tshark -r $p -q -z endpoints,ip 2>$null | Select-String '^\d+\.\d+\.\d+\.\d+').Count
    S7_Identity  = Count $p "s7comm.data.userdata.szl_id"
    Modbus_FC43  = Count $p "modbus.func_code == 43"
    PN_DCP       = Count $p "pn_dcp.suboption_device_nameofstation || pn_dcp.suboption_vendor_id"
    CIP_Identity = Count $p "cip.id.product_name"
    SHA256       = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
  }
}
$rows | Export-Csv $out -NoTypeInformation
$rows | Format-Table File, Packets, IPs, S7_Identity, Modbus_FC43, PN_DCP, CIP_Identity -AutoSize