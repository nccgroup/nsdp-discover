# nsdp-discover
An Nmap script to identify Netgear Switch Discovery Protocol (NSDP) on UDP ports 63322 and 63324.

The script tries to send a discovery request and creates a UDP server to listen for responses.

Information recovered from this script includes: Device Type, Name, MAC, Location, IP, Netmask, Gateway, Firmware versions and current firmware.

## Usage

`nmap -sU -p 63322,63324 --script=nsdp-discover <ip> `

<pre>
PORT      STATE SERVICE
63322/udp open  nsdp
| nsdp-discover:
|   Model: JGS516PE
|   Name: Test
|   MAC: 00:00:00:00:00:00
|   Location:
|   IP: 192.168.0.239
|   Netmask: 255.255.255.0
|   Gateway: 192.168.0.254
|   Active_Firmware: 1
|   FW_Version_1: 2.6.0.43
|_  FW_Version_2: 2.6.0.24
</pre>
