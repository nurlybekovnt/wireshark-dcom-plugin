-- Set meta-data about the plugin
local plugin_info = {
  version = "0.0.2",
  author = "Nadirbek Nurlybekov",
  repository = "https://github.com/nurlybekovnt/wireshark-dcom-plugin"
}
set_plugin_info(plugin_info)


-- Define a protocol for our dissector
dcom_protocol = Proto("dcom_protocol", "DCOM Protocol")


-- Define the fields we want to extract from the packet

-- DCOM header fields
dcom_protocol.fields.cookie = ProtoField.uint32("dcom_protocol.cookie", "Cookie", base.DEC_HEX)
dcom_protocol.fields.version = ProtoField.uint16("dcom_protocol.version", "Version")
dcom_protocol.fields.message_type = ProtoField.uint32(
  "dcom_protocol.message_type",
  "Message Type",
  base.DEC,
  {
    [9] = "Location Update",
    [10] = "Heartbeat"
  }
)
dcom_protocol.fields.pp_ver = ProtoField.uint16("dcom_protocol.pp_ver", "PpVer", base.DEC_HEX)
dcom_protocol.fields.dispatch_type = ProtoField.uint32("dcom_protocol.dispatch_type", "Dispatch Type", base.DEC_HEX)
dcom_protocol.fields.dispatch_arg = ProtoField.bytes("dcom_protocol.dispatch_arg", "Dispatch Argument")
dcom_protocol.fields.reserved = ProtoField.bytes("dcom_protocol.reserved", "Reserved")
dcom_protocol.fields.data_length = ProtoField.uint16("dcom_protocol.data_length", "Data Length")
dcom_protocol.fields.filler = ProtoField.bytes("dcom_protocol.filler", "Filler")

-- DCOM Heartbeat fields in v0.2
dcom_protocol.fields.source_name_len = ProtoField.uint8("dcom_protocol.heartbeat.source_name_len", "SourceNameLen")
dcom_protocol.fields.source_name = ProtoField.string("dcom_protocol.heartbeat.source_name", "SourceName")

-- DCOM Location Update fields in v0.1
dcom_protocol.fields.net_unit_group_id =
    ProtoField.uint32("dcom_protocol.location_update.net_unit_group_id", "NetUnitGroupID")
dcom_protocol.fields.net_unit_id = ProtoField.uint32("dcom_protocol.location_update.net_unit_id", "NetUnitID")
dcom_protocol.fields.msisdn = ProtoField.uint64("dcom_protocol.location_update.msisdn", "MSISDN")

-- DCOM Location Update fields in v0.2
dcom_protocol.fields.flags = ProtoField.uint8(
  "dcom_protocol.location_update.flags",
  "Flags",
  base.DEC,
  {
      [0] = "LBE no",
      [1] = "LBE yes"
  }
)
dcom_protocol.fields.uli_len = ProtoField.uint8("dcom_protocol.location_update.uli_len", "ULILen")
dcom_protocol.fields.uli = ProtoField.bytes("dcom_protocol.location_update.uli", "ULI")


-- dcom_protocol.prefs.ether_addresses = Pref.string("Ethernet addresses", "ff:ff:ff:ff:ff:ff", "Comma-separated Ethernet addresses for identifying DCOM packets")
local eth_dst = Field.new("eth.dst")
local eth_src = Field.new("eth.src")
local function is_dcom_packet()
  local addr_dst = eth_dst()
  local addr_src = eth_src()
  if not eth_dst and not eth_src then
    return false
  end
  for addr_str in string.gmatch(dcom_protocol.prefs.ether_addresses, '([^,]+)') do
    local addr = Address.ether(addr_str)
    if addr_dst and addr_dst.value == addr then
      return true
    end
    if addr_src and addr_src.value == addr then
      return true
    end
  end
  return false
end


-- Define the dissector function
function dcom_protocol.dissector(buffer, pinfo, tree)
  if buffer:len() < 45 then return end

  local subtree = tree:add(dcom_protocol, buffer())

  -- Add fields to the display tree
  subtree:add(dcom_protocol.fields.cookie, buffer(0, 4))
  subtree:add(dcom_protocol.fields.version, buffer(4, 2))
  subtree:add(dcom_protocol.fields.message_type, buffer(6, 4))
  subtree:add(dcom_protocol.fields.pp_ver, buffer(10, 2))
  subtree:add(dcom_protocol.fields.dispatch_type, buffer(12, 4))
  subtree:add(dcom_protocol.fields.dispatch_arg, buffer(16, 16))
  subtree:add(dcom_protocol.fields.reserved, buffer(32, 13))
  subtree:add(dcom_protocol.fields.data_length, buffer(45, 2))

  local message_type = buffer(6, 4):uint()
  if message_type == 10 then
    -- it's a heartbeat
    pinfo.cols.protocol:set("DCOM v0.2 Heartbeat")
    subtree:add(dcom_protocol.fields.source_name_len, buffer(47, 1))

    local len = buffer(47, 1):uint()
    subtree:add(dcom_protocol.fields.source_name, buffer(48, len))
    subtree:add(dcom_protocol.fields.filler, buffer(48 + len, 64 - len))
  elseif message_type == 9 then
    -- it's a location update
    local data_length = buffer(45, 2):uint()
    if data_length == 16 then
      -- Set the protocol column in Wireshark
      pinfo.cols.protocol:set("DCOM v0.1 Location Update")
      subtree:add(dcom_protocol.fields.net_unit_group_id, buffer(47, 4))
      subtree:add(dcom_protocol.fields.net_unit_id, buffer(51, 4))
      subtree:add(dcom_protocol.fields.msisdn, buffer(55, 8))
    elseif data_length == 82 then
      -- Set the protocol column in Wireshark
      pinfo.cols.protocol:set("DCOM v0.2 Location Update")
      subtree:add(dcom_protocol.fields.flags, buffer(47, 1))
      subtree:add(dcom_protocol.fields.net_unit_group_id, buffer(48, 4))
      subtree:add(dcom_protocol.fields.net_unit_id, buffer(52, 4))
      subtree:add(dcom_protocol.fields.msisdn, buffer(56, 8))
      subtree:add(dcom_protocol.fields.uli_len, buffer(64, 1))

      local uli_len = buffer(64, 1):uint()
      subtree:add(dcom_protocol.fields.uli, buffer(65, uli_len))
      subtree:add(dcom_protocol.fields.filler, buffer(65 + uli_len, 64 - uli_len))
    end
  end
end

--- Heuristic check for DCOM protocol. This function checks if a packet is a
-- DCOM packet by comparing its Ethernet addresses with a predefined
-- DCOM Ethernet address. If the packet is a DCOM packet, it calls the DCOM
-- dissector function to dissect the packet.
--
-- @param buffer The buffer containing the packet data.
--
-- @param pinfo Packet information.
--
-- @param tree The tree to add dissected data.
--
-- @return true if the packet is a DCOM packet, false otherwise.
local function heuristic_dissector_check(buffer, pinfo, tree)
  print("running Heuristic check for DCOM protocol")
  if is_dcom_packet() then
    dcom_protocol.dissector(buffer, pinfo, tree)
    return true
  end
  return false
end

-- dcom_protocol:register_heuristic("udp", heuristic_dissector_check)
-- dcom_protocol:register_heuristic("tcp", heuristic_dissector_check)

-- For the "Decode As..." dialog
-- DissectorTable.get("udp.port"):add_for_decode_as(dcom_protocol)
-- DissectorTable.get("tcp.port"):add_for_decode_as(dcom_protocol)

local function redissect_all_packets_with_dcom()
  local all_ports = "0-65535"
  DissectorTable.get("udp.port"):add(all_ports, dcom_protocol)
  DissectorTable.get("tcp.port"):add(all_ports, dcom_protocol)
  reload_packets()
end

register_menu("Reprocess with DCOM", redissect_all_packets_with_dcom, MENU_TOOLS_UNSORTED)
