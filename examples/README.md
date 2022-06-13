# Examples

| File                         | Description                                                                                     |
|------------------------------|-------------------------------------------------------------------------------------------------|
| [sni.lua](sni.lua)           | Prints the TLS SNI (host-name) of every TCP ClientHello received                                |
| [hits.lua](hits.lua) | Inspect every TLS Client Hello and accumulate the number of hits per SNI                                |
| [no-more-http.lua](no-more-http.lua) | Exchanges unencrypted HTTP responses with a static custom response (**ARP SPOOF only**) |
| [block.lua](block.lua)       | Blocks all network traffic going to a specific service (**ARP SPOOF only**)                     |
| [block-all.lua](block-all.lua) | Blocks all network traffic (**ARP SPOOF only**)                                               |
| [block-http.lua](block-http.lua) | Blocks all unencrypted HTTP traffic (**ARP SPOOF only**)                                    |
| [dns.lua](dns.lua) | Checks for a specific DNS requests and changes its response to some custom IP address (**ARP SPOOF ONLY**) |


> **NOTE:** Examples flagged with **ARP SPOOF ONLY** will also run under the `inspect` command, they won't have their intended effect however.
