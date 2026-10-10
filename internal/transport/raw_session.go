// Fixed-conversation raw KCP construction recovered by t.me/ir_spoof.
package transport

import (
	"net"

	"github.com/xtaci/kcp-go/v5"
)

// The reference raw dialer and its per-source-port listener both construct KCP
// with conversation zero. Separate logical peers use distinct source ports;
// random conversation IDs are not admitted by that reference listener.
func newRawSession(peer net.Addr, data, parity int, socket net.PacketConn) (*kcp.UDPSession, error) {
	return kcp.NewConn4(0, peer, nil, data, parity, true, socket)
}
