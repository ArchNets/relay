<!-- Independent reconstruction by ir_spoof; https://t.me/ir_spoof. -->

L2TP forwarding uses recovered UDP DNAT to the same destination port and UDP
MASQUERADE on the TUN interface. Default ports are 500, 4500 and 1701. An explicit
`l2tp_dest_ip` overrides the local TUN IP. This forwards IPsec/L2TP traffic; it
does not itself implement an IPsec or L2TP server.

The rebuild creates random invocation-specific NAT chains, adds identifiable
parent-chain jumps after populating them, and removes only those chains/jumps
on normal shutdown or installation failure. MASQUERADE is restricted to the destination IP.
It does not flush shared chains or change forwarding/sysctl/firewall policy.
For a destination outside the local TUN IP, the administrator must enable IPv4
forwarding and permit routed UDP explicitly. Local destinations need an IPsec/
L2TP service and matching input firewall rules.
Unclean termination can leave owned rules requiring manual removal.
