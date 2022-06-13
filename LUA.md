# Lua

In this document, I will be explaining how to interact with harpy from inside the Lua script.

## Lua API

Harpy facilitates a mechanic to manipulate network traffic through the high-performant scripting language [Lua](https://www.lua.org/).

Lua scripts are evaluated once during startup and then remains in memory.
This means that, as of now, you can't update the script while the application is running.

The layout and variables of this Lua file is up to you, but it should contain an `on_packet` function that will be called on every packet received.
This function shall take a single argument, the Lua representation of an [Ethernet frame](https://en.wikipedia.org/wiki/Ethernet_frame), conversely named [LuaEthernetFrame](#luaethernetframe).

The method signature of `on_packet` is thereby `function on_packet(ethernet_frame)`, for ARP spoofing purposes it is necessary to later return the same `ethernet_frame` from the function, else wise changes to payload, etc. won't be flushed.

## Examples

Practical examples of how the Lua API can be used can be found in [examples/](examples/).


## Variables and Functions

Harpy exports specialized functions and variables that can be used in the Lua script.

### Variables
* `MTU` – The MTU of the interface that harpy is running on.
* `harpy_version` – The version of harpy that is running
* `harpy_mode` – Currently either `spoof` or `inspect`

### Functions
* `binary(string) -> LuaBinary`
Creates a binary table from all sorts of data, strings, raw byte tables, etc.

* `binary_to_string(binary: LuaBinary) -> string`
Returns a string constructed by the binary data passed, no validity checking is performed, the returned string may be utter junk.


## Types

### `LuaEthernetFrame`
---

#### `LuaEthernetFrame:src() -> string`
Returns the source MAC address of the Ethernet frame.

#### `LuaEthernetFrame:dst() -> string`
Returns the destination MAC address of the Ethernet frame.

#### `LuaEthernetFrame:type() -> string`
Returns the frames' ether type as a string.

Possible strings are: `Ipv4`, `Arp`, `WakeOnLan`, `Trill`, `DECnet`, `Rarp`, `AppleTalk`, `Aarp`, `Ipx`, `Qnx`, `Ipv6`, `FlowControl`, `CobraNet`, `Mpls`, `MplsMcast`, `PppoeDiscovery`, `PppoeSession`, `Vlan`, `PBridge`, `Lldp`, `Ptp`, `Cfm`, `QinQ`

#### `LuaEthernetFrame:payload([new_payload: LuaBinary|LuaIpv4Packet|...]) -> LuaBinary|nil`
If `new_payload` is nil, returns the payload of the Ethernet frame as `LuaBinary`.

Else, sets the payload of the Ethernet frame to the passed `LuaBinary`.

The argument can be either a raw binary (`LuaBinary`), or some other user data that corresponds to some layer 3 protocol (IPv4, etc.).
f.e. a `LuaTcpPacket` or a `LuaUdpPacket`.

> **NOTE:** Make sure that the new payload is smaller than `MTU`
> **NOTE:** Setting the payload will only have an effect if you are ARP spoofing.

#### `LuaEthernetFrame:drop()`
Flags the Ethernet frame to be dropped.
> **NOTE:** This will only work if you are ARP spoofing, and also requires you to return the dropped ethernet frame.

#### `LuaEthernetFrame:size() -> integer`
Returns the entire size of the Ethernet frame, including header and payload.

#### `LuaEthernetFrame:ipv4() -> LuaIpv4Packet|nil`
If the Ethernet frame is an IPv4 packet, returns the IPv4 packet, if it isn't, returns nil.

#### `LuaEthernetFrame:ipv6() -> LuaIpv6Packet|nil`
If the Ethernet frame is an IPv6 packet, returns the IPv6 packet, if it isn't, returns nil.


### `LuaIpv4Packet`
---

#### `LuaIpv4Packet:src() -> string`
Returns the source IP address of the IPv4 packet.

#### `LuaIpv4Packet:dst() -> string`
Returns the destination IP address of the IPv4 packet.

#### `LuaIpv4Packet:protocol() -> string`
Returns the protocol of the IPv4 packet as a string.

There are too many protocols to list here, but the following strings should give you an idea of what they usually look like:
`Tcp`, `Udp`, `Icmp`, `Igmp`

#### `LuaIpv4Packet:payload([new_payload: LuaBinary|LuaTcpPacket|LuaUdpPacket]) -> LuaBinary|nil`
If `new_payload` is nil, returns the payload of the IPv4 packet as a `LuaBinary`.

Else, sets the payload of the IPv4 packet to the passed argument and returns nil.

The argument can be either a raw binary (`LuaBinary`), or some other user data that corresponds to some layer 4 protocol (TCP, UDP, etc.).
f.e. a `LuaTcpPacket` or a `LuaUdpPacket`.

> **NOTE:** Setting the payload will only work if you are ARP spoofing.


#### `LuaIpv4Packet:tcp() -> LuaTcpPacket|nil`
If the IPv4 packet is a TCP packet, returns the TCP packet, if it isn't, returns nil.

#### `LuaIpv4Packet:udp() -> LuaUdpPacket|nil`
If the IPv4 packet is a UDP packet, returns the UDP packet, if it isn't, returns nil.

### `LuaUdpPacket`
---
#### `LuaUdpPacket:src_port() -> integer`
Returns the source port of the UDP packet.

#### `LuaUdpPacket:dst_port() -> integer`
Returns the destination port of the UDP packet.

#### `LuaUdpPacket:size() -> integer`
Returns the size of the UDP packet.

#### `LuaUdpPacket:payload([new_payload: LuaBinary]) -> table`
If `new_payload` is nil, returns the payload of the UDP packet as `LuaBinary`.

Else, sets the payload of the IPv4 packet to the passed argument and returns nil.

> **NOTE:** Setting the payload will only have an effect if you are ARP spoofing.



### `LuaTcpPacket`
---
#### `LuaTcpPacket:src_port() -> integer`
Returns the source port of the TCP packet.

#### `LuaTcpPacket:dst_port() -> integer`
Returns the destination port of the TCP packet.

#### `LuaTcpPacket:size() -> integer`
Returns the size of the TCP packet, including payload and header.

#### `LuaTcpPacket:seq() -> integer`
Returns the sequence number of the TCP packet.

#### `LuaTcpPacket:ack() -> integer`
Returns the acknowledgement number of the TCP packet.

#### `LuaTcpPacket:flags() -> integer`
Returns the flags of the TCP packet. More information about the flags can be found [here](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure).

#### `LuaTcpPacket:window() -> integer`
Returns the window size of the TCP packet.

#### `LuaTcpPacket:checksum() -> string`
Returns the checksum of the TCP packet.

#### `LuaTcpPacket:urgent() -> string`
Returns the urgent pointer of the TCP packet.

#### `LuaTcpPacket:is_tls() -> boolean`
Returns true if the TCP packet contains TLS data.

#### `LuaTcpPacket:tls() -> LuaTlsPacket|nil`
If the TCP packet contains TLS data, returns a special TLS wrapper, if it doesn't, returns nil.

#### `LuaTcpPacket:payload([new_payload: LuaBinary]) -> LuaBinary`
If `new_payload` is nil, returns the payload of the TCP packet as `LuaBinary`.

Else, sets the payload of the IPv4 packet to the passed argument and returns nil.

> **NOTE:** Setting the payload will only have an effect if you are ARP spoofing.


### `LuaTls`
---
#### `LuaTls:version() -> string`
Returns the version of the TLS packet.

#### `LuaTls:content_type() -> integer`
Returns the content type of the TLS packet. More information about the content types can be found [here](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record).

#### `LuaTls:size() -> integer`
Returns the size of the TLS packet, only including payload.

#### `LuaTls:client_hello() -> LuaClientHello|nil`
If the TLS content type is client hello, returns the client hello, if it isn't, returns nil.


### `LuaClientHello`
---
#### `LuaClientHello:sni() -> string|nil`
Returns the server name indication of the client hello, if none was sent, returns nil.

#### `LuaClientHello:ciphersuites() -> table`
Returns the cipher suites of the client hello as a table of strings.

#### `LuaClientHello:signature_schemes() -> table`
Returns the signature schemes of the client hello as a table of strings.



