# Harpy
![GitHub](https://img.shields.io/github/license/27justin/harpy)

Harpy, or hARPy, is a program to inspect your network traffic, or to inspect and manipulate traffic of another host on your network through ARP spoofing.

-- Video goes here --


# Features

## ARP spoofing

[Poison the ARP cache of a target host](https://en.wikipedia.org/wiki/ARP_spoofing) to coax it into sending its traffic to your host, which in turn will redirect the traffic from the victim to the default gateway.

If you are ARP spoofing, you can inspect, modify and even drop packets of the host you are spoofing.

## Inspecting local network traffic

You can also opt to monitor the traffic of your machine using the [`inspect`](#inspecting-traffic) subcommand.

However, keep in mind that features like dropping and modifying packets are not available in this mode, as harpy only listens to the packets and does not embed itself into your network stack.



# Building from source

For starters, install all the dependencies required for harpy

* libpcap
    * Debian-based: `apt install libpcap0.8 libpcap-dev`
    * Arch-based: `pacman -S libpcap`

## Compiling

`cargo build --release`

If the process finished without errors, the compiled binary will be at `./target/release/harpy`

# Usage

Foremost, you have to provide a Lua script which handles the inspection/manipulation.

The Lua script can be given through the `-f` argument.

The file will be interpreted once on startup and remain in memory.
Therefore, you can't update the script while the application is running.

The script **HAS** to contain an `on_packet(eth_frame)` function that will be called on every packet received.

For more information, see the [Lua API](LUA.md)

Example scripts, can be found in the [examples](examples/) subdirectory.

---
## ARP spoofing

> **NOTE:** Depending on your hardware, you may want to turn off [TCP offloading](#tcp-offloading) to fully facilitate ARP spoofing capabilities.

```
USAGE:
    harpy spoof [OPTIONS] --target <TARGET> --interface <INTERFACE>

OPTIONS:
    -a, --all                      Capture all traffic instead of just traffic between the gateway
                                   and the target
    -f, --file <FILE>              The lua file to interpret
    -g, --gateway <GATEWAY>        The interface to use, defaults to the first one found
    -h, --help                     Print help information
    -i, --interface <INTERFACE>    The interface to use
    -t, --target <TARGET>          The target IP address to spoof
```

e.g.
```
harpy spoof -i enp7s0 -f examples/sni.lua -t 192.168.0.53
```

---
## Inspecting traffic

```
USAGE:
    harpy inspect --file <FILE> --interface <INTERFACE>

OPTIONS:
    -f, --file <FILE>
    -h, --help                     Print help information
    -i, --interface <INTERFACE>
```
e.g.
```
harpy inspect -f examples/hits.lua -i enp7s0
```


# Planned features

* Support for the UDP QUIC protocol
* Reloading the Lua script if necessary (e.g., if the file changes)
* Spoofing multiple hosts
* Manipulating packets source and destination (including destination for TCP, UDP, etc.)
* Constructing and sending handcrafted packets
* Warning on unexpected types for built-in Lua functions


# Troubleshooting

## TCP Offloading

If you were ARP spoofing and the binary crashed with an error message, somewhat like this:
```
An unexpected error occured. Maybe you have TCP offloading enabled?
Os {
    code: 90,
    kind: Uncategorized,
    message: "Message too long",
}
```
Then you may want to temporarily switch off TCP offloading.

TCP offloading causes raw network sockets to receive packets bigger than the MTU of the network interface.

It does this by concatenating related TCP streams into one big frame.

This big frame then can't be flushed back to your gateway, causing the packet to be inadvertently dropped.

With disabled TCP offloading, harpy will receive all individual Ethernet frames, smaller or at the MTU of your NIC.
<details>
    <summary>
        You can turn off TCP offloading with the following commands:
    </summary>
<pre>
sudo ethtool -K &lt;interface&gt; generic-segmentation-offload off
sudo ethtool -K &lt;interface&gt; generic-receive-offload off
sudo ethtool -K &lt;interface&gt; tcp-segmentation-offload off
sudo ethtool -K &lt;interface&gt; udp-fragmentation-offload off
sudo ethtool -K &lt;interface&gt; rx-vlan-offload off
sudo ethtool -K &lt;interface&gt; tx-vlan-offload off
</pre>
</details>

# Support

Contributions, issues, feature requests, and pull requests are all very much welcome.


