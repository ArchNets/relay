<!-- Linux TUN implementation by ir_spoof; https://t.me/ir_spoof. -->
# Owned Linux TUN devices

`Open(name, localCIDR, mtu, queues, routes)` creates a new, nonpersistent Linux
TUN interface. `Queue(index)` returns one packet-oriented reader/writer;
`Close()` cancels blocked reads and closes every queue. The interface disappears
when its final descriptor closes. Names already present in the current network
namespace are rejected.

The caller needs permission to open `/dev/net/tun` and `CAP_NET_ADMIN` in its
network namespace. Configuration uses a system `ip` executable with separate
arguments, never shell interpolation. Routes are added without replacing any
existing route. Cleanup tracks only successfully added routes and the original
interface index. No discovery request, vendor contact or firewall command runs
in this package.

Reads consume complete packets. Allocate `MaxPacketSize` bytes (65,535) for the
destination; an undersized buffer returns `io.ErrShortBuffer` instead of silently
truncating a packet. Writes above that bound fail before reaching the kernel.

The privileged tests deliberately require `NETRIX_TUN_LAB=1`, root, and a network
namespace different from PID 1's namespace. Run them only in a disposable Linux
lab, for example:

```sh
unshare -n env NETRIX_TUN_LAB=1 go test -v ./internal/tun
```

The tests cover two queues, cancellation, MTU/address/route setup, refusal to
reuse an existing interface, failed-configuration rollback, preservation of an
unrelated route, and packet buffer bounds. They do not assert compatibility with
any proprietary peer protocol; the network record codec belongs to the core.
