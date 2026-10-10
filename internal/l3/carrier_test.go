// Recovered L3 outer-header vectors by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"netrix.local/ir_spoof/internal/packet"
)

func TestRuntimeICMPIdentifierMatchesReferenceCapture(t *testing.T) {
	c := basicConfig()
	c.PSK = "ir_spoof-isolated-fixture-v3"
	c.Tun.Local, c.Tun.Remote = "198.18.0.1/30", "198.18.0.2/30"
	c.L3.Carrier, c.L3.ICMPType = "icmp", 8
	s, err := loadSettings(c)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := s.scope.SessionID()
	if err != nil || sid != 0xe232e3cf || s.packet.ICMPIdentifier == nil || *s.packet.ICMPIdentifier != 509 {
		t.Fatalf("recovered ICMP scope/identifier: sid=%08x options=%+v err=%v", sid, s.packet, err)
	}
	frame, err := packet.EncodeIPv4(s.packet, []byte("opaque record"), 42)
	if err != nil || binary.BigEndian.Uint16(frame[24:26]) != 509 {
		t.Fatal("wire identifier is not the captured reference value", err)
	}
	for _, sid := range []uint32{0, 0x11111111, 0xffffffff} {
		if icmpIdentifier(sid) != 0x4e45 {
			t.Fatalf("zero fold must use recovered sentinel for %08x", sid)
		}
	}
}

func TestRuntimeSourceSpoofingKeepsRealPeerDestination(t *testing.T) {
	c := basicConfig()
	c.PSK = "ir_spoof-isolated-fixture-v3"
	c.Tun.Local, c.Tun.Remote = "198.18.0.1/30", "198.18.0.2/30"
	c.L3.Carrier, c.L3.Interface = "raw", "lab0"
	c.L3.SpoofSrcIP, c.L3.SpoofDstIP = "192.0.2.101", "192.0.2.102"
	server, err := loadSettings(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Mode = "client"
	c.L3.ListenIP, c.L3.DstIP = c.L3.DstIP, c.L3.ListenIP
	c.L3.SpoofSrcIP, c.L3.SpoofDstIP = c.L3.SpoofDstIP, c.L3.SpoofSrcIP
	c.Tun.Local, c.Tun.Remote = c.Tun.Remote, c.Tun.Local
	client, err := loadSettings(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*settings{server, client} {
		sid, err := s.scope.SessionID()
		if err != nil || sid != 0x0dc0f91d || len(s.packet.SpoofDstIP) != 0 || !s.packet.ReceiveDstIP.Equal(s.packet.LocalIP) || !s.packet.ReceiveSrcIP.Equal(net.ParseIP(s.scope.SpoofDstIP)) {
			t.Fatalf("recovered source-spoof adapter changed scope or admission: %08x %+v %v", sid, s.packet, err)
		}
	}
	for _, pair := range [][2]*settings{{server, client}, {client, server}} {
		sender, receiver := pair[0], pair[1]
		frame, err := packet.EncodeIPv4(sender.packet, []byte("opaque record"), 42)
		if err != nil || !net.IP(frame[12:16]).Equal(net.ParseIP(sender.scope.SpoofSrcIP)) || !net.IP(frame[16:20]).Equal(sender.packet.PeerIP) {
			t.Fatal("reference sends spoofed source to real peer", err)
		}
		if data, err := packet.DecodeIPv4(receiver.packet, frame); err != nil || string(data) != "opaque record" {
			t.Fatalf("mirrored reference address admission: %q %v", data, err)
		}
		bad := append([]byte(nil), frame...)
		copy(bad[16:20], net.ParseIP(sender.scope.SpoofDstIP).To4())
		binary.BigEndian.PutUint16(bad[10:12], 0)
		binary.BigEndian.PutUint16(bad[10:12], packet.Checksum(bad[:20]))
		if _, err := packet.DecodeIPv4(receiver.packet, bad); !errors.Is(err, packet.ErrAdmission) {
			t.Fatal("spoofed destination bypassed real-local admission", err)
		}
	}
}
