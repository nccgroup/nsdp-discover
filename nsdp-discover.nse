local string = require "string"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Attempts to retrieve basic device information from Netgear Switch Discovery Protocol [NSDP] (UDP ports 63322 and 63324). The script tries to send a discovery request and creates a UDP server to listen for responses.

Information recovered from this script includes: Device Type, Name, MAC, Location, IP, Netmask, Gateway, Firmware versions and current firmware.

The information related to NSDP protocol was the result of a NSDP security research that can be found at https://research.nccgroup.com/
]]

---
-- @usage
-- nmap -sU -p 63322,63324 --script=nsdp-discover <ip>
--
-- @output
-- PORT      STATE SERVICE
-- 63322/udp open  nsdp
-- | nsdp-discover:
-- |   Model: JGS516PE
-- |   Name: Test
-- |   MAC: 00:00:00:00:00:00
-- |   Location:
-- |   IP: 192.168.0.239
-- |   Netmask: 255.255.255.0
-- |   Gateway: 192.168.0.254
-- |   Active_Firmware: 1
-- |   FW_Version_1: 2.6.0.43
-- |_  FW_Version_2: 2.6.0.24
--
-- @xmloutput
-- <elem key="Model">JGS516PE</elem>
-- <elem key="Name">Test</elem>
-- <elem key="MAC">\x00\x00\x00\x00\x00\x00</elem>
-- <elem key="Location"></elem>
-- <elem key="IP">192.168.0.239</elem>
-- <elem key="Netmask">255.255.255.0</elem>
-- <elem key="Gateway">192.168.0.254</elem>
-- <elem key="Active_Firmware">1</elem>
-- <elem key="FW_Version_1">2.6.0.43</elem>
-- <elem key="FW_Version_2">2.6.0.24</elem>

author = "Manuel Gines @ NCC Group"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.portnumber({63322, 63324}, "udp")

action = function(host, port)
  if not port then return end

  local results = stdnse.output_table()

  local udp = nmap.new_socket('udp')
  local catch = function()
    print("Error")
    client:close()
  end
  local try = nmap.new_try(catch)

  try(udp:set_timeout(1000))

  if (port.number == 63322) then
    try(udp:bind(nil,63321))
  else
    try(udp:bind(nil,63323))
  end

  local interfaces, err = nmap.list_interfaces()
  for i, iface in ipairs(interfaces) do
    if (iface["mac"]) then
      local packet = "\x01\x01\x00\x00\x00\x00\x00\x00" .. iface["mac"] .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x4e\x53\x44\x50\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x06\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x0b\x00\x00\x00\x0c\x00\x00\x00\x0d\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\xff\xff\x00\x00"

      try(udp:sendto(host.ip,port.number,packet))
      local status, data = udp:receive()

      if (status and data:len() > 33) then
        local tlvs = data:sub(33)
        local i = 1
        local product = "Netgear Switch"

        while (i < tlvs:len()) do
          local cmd = string.unpack(">I2", tlvs:sub(i+0,i+1))
          local len = string.unpack(">I2", tlvs:sub(i+2,i+3))
          local data = tlvs:sub(i+4,i+3+len)

          if (cmd == 1) then results["Model"] = data end
          if (cmd == 3) then results["Name"] = data end
          if (cmd == 4) then results["MAC"] = data end
          if (cmd == 5) then results["Location"] = data end
          if (cmd == 6) then results["IP"] = string.unpack(">I1", data:sub(1,1)) .. "." .. string.unpack(">I1", data:sub(2,2)) .. "." .. string.unpack(">I1", data:sub(3,3)) .. "." .. string.unpack(">I1", data:sub(4,4)) end
          if (cmd == 7) then results["Netmask"] = string.unpack(">I1", data:sub(1,1)) .. "." .. string.unpack(">I1", data:sub(2,2)) .. "." .. string.unpack(">I1", data:sub(3,3)) .. "." .. string.unpack(">I1", data:sub(4,4)) end
          if (cmd == 8) then results["Gateway"] = string.unpack(">I1", data:sub(1,1)) .. "." .. string.unpack(">I1", data:sub(2,2)) .. "." .. string.unpack(">I1", data:sub(3,3)) .. "." .. string.unpack(">I1", data:sub(4,4)) end
          if (cmd == 12) then results["Active_Firmware"] = string.unpack(">I1", data) end
          if (cmd == 13) then results["FW_Version_1"] = data end
          if (cmd == 14) then results["FW_Version_2"] = data end
          i = i + 4 + len
        end

        nmap.set_port_state(host, port, "open")
        port.version.name = "nsdp"
        port.version.product = product
        nmap.set_port_version(host, port, "softmatched")
        return results
      end
    end
  end

  return results
end