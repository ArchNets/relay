// Scoped ICMP capture admission by ir_spoof; https://t.me/ir_spoof.
//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestLinuxOwnedICMPFilterValidatesRecoveredIdentifier(t *testing.T) {
	identifier := uint16(509)
	value := options("icmp")
	value.ICMPIdentifier = &identifier
	codec, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := EncodeIPv4(opposite(value), []byte("opaque record"), 1)
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:42:01")
	peerMAC, _ := net.ParseMAC("02:00:00:00:42:02")
	for _, ethernet := range []bool{false, true} {
		connection := &socketConn{codec: codec, ethernet: ethernet, localMAC: mac}
		vm := filterVM(t, connection.socketFilter())
		for _, wrong := range []uint16{509, 0, 40001} {
			wire := append([]byte(nil), frame...)
			binary.BigEndian.PutUint16(wire[24:26], wrong)
			if ethernet {
				wire, err = EncodeEthernet(peerMAC, mac, wire)
				if err != nil {
					t.Fatal(err)
				}
			}
			n, err := vm.Run(wire)
			if err != nil || (n > 0) != (wrong == 509) {
				t.Fatalf("ICMP filter identifier=%d ethernet=%v result=%d: %v", wrong, ethernet, n, err)
			}
		}
	}
}
