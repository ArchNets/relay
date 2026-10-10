// Local route/ARP fixture tests by ir_spoof; https://t.me/ir_spoof.
//go:build linux

package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
)

func TestLinuxRouteNeighborParsingAndARPAdmission(t *testing.T) {
	local, peer := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	mac, _ := net.ParseMAC("02:00:00:00:42:01")
	remote, _ := net.ParseMAC("02:00:00:00:42:02")
	hop, err := routeNextHop([]byte(`[{"dev":"lab0"}]`), "lab0", peer)
	if err != nil || !hop.Equal(peer) {
		t.Fatal("direct route", err)
	}
	hop, err = routeNextHop([]byte(`[{"dev":"lab0","gateway":"192.0.2.254"}]`), "lab0", peer)
	if err != nil || hop.String() != "192.0.2.254" {
		t.Fatal("gateway route", err)
	}
	for _, data := range []string{`[{"dev":"foreign"}]`, `[{"dev":"lab0","gateway":"224.0.0.1"}]`, `[]`} {
		if _, err := routeNextHop([]byte(data), "lab0", peer); err == nil {
			t.Fatal("bad route admitted")
		}
	}
	resolved, err := neighborMAC([]byte(`[{"dst":"192.0.2.2","lladdr":"02:00:00:00:42:02"}]`), peer)
	if err != nil || !bytes.Equal(resolved, remote) {
		t.Fatal("neighbor", err)
	}
	request, err := arpRequest(mac, local, peer)
	if err != nil || len(request) != 42 || !bytes.Equal(request[:6], bytes.Repeat([]byte{255}, 6)) || !net.IP(request[38:42]).Equal(peer) {
		t.Fatal("ARP request", err)
	}
	reply, err := arpRequest(remote, peer, local)
	if err != nil {
		t.Fatal(err)
	}
	copy(reply[:6], mac)
	copy(reply[32:38], mac)
	binary.BigEndian.PutUint16(reply[20:22], 2)
	got, err := arpReplyMAC(reply, mac, local, peer)
	if err != nil || !bytes.Equal(got, remote) {
		t.Fatal("valid ARP", err)
	}
	for _, offset := range []int{0, 6, 14, 16, 18, 19, 20, 28, 32, 38} {
		bad := append([]byte(nil), reply...)
		bad[offset] ^= 1
		if _, err := arpReplyMAC(bad, mac, local, peer); err == nil {
			t.Fatalf("ARP foreign tuple %d", offset)
		}
	}
	for n := 0; n < 42; n++ {
		if _, err := arpReplyMAC(reply[:n], mac, local, peer); err == nil {
			t.Fatal("truncated ARP")
		}
	}
	if _, err := arpReplyMAC(request, mac, local, peer); err == nil || errors.Is(err, ErrFragmentPending) {
		t.Fatal("request accepted as reply")
	}
}

func TestLinuxIsolatedLabRouterMACResolution(t *testing.T) {
	if os.Getenv("NETRIX_PACKET_ARP_TEST") != "1" {
		t.Skip("explicit isolated namespace fixture required")
	}
	mac, err := ResolveRouterMAC("lab0", net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"))
	if err != nil || mac.String() != "02:00:00:00:42:02" {
		t.Fatalf("isolated neighbor resolution %v %v", mac, err)
	}
}
