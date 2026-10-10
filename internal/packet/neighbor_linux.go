// Local route/neighbor resolution by ir_spoof; https://t.me/ir_spoof.
//go:build linux

package packet

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type routeEntry struct {
	Interface string `json:"dev"`
	Gateway   string `json:"gateway"`
}
type neighborEntry struct {
	Destination string `json:"dst"`
	MAC         string `json:"lladdr"`
}

func localIPCommand(arguments ...string) ([]byte, error) {
	helper, err := trustedHelper("ip")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, arguments...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stderr = io.Discard
	output := &limitedCaptureOutput{limit: 64 << 10}
	cmd.Stdout = output
	if err = cmd.Run(); err != nil {
		return nil, fmt.Errorf("packet: local route/neighbor lookup failed")
	}
	return output.Bytes(), nil
}

func routeNextHop(data []byte, iface string, peer net.IP) (net.IP, error) {
	var entries []routeEntry
	if json.Unmarshal(data, &entries) != nil || len(entries) != 1 || entries[0].Interface != iface {
		return nil, fmt.Errorf("packet: no matching local interface route")
	}
	if entries[0].Gateway == "" {
		return append(net.IP(nil), peer.To4()...), nil
	}
	hop := net.ParseIP(entries[0].Gateway)
	if _, err := ipv4(hop); err != nil {
		return nil, fmt.Errorf("packet: route gateway is not unicast IPv4")
	}
	return append(net.IP(nil), hop.To4()...), nil
}

func neighborMAC(data []byte, hop net.IP) (net.HardwareAddr, error) {
	var entries []neighborEntry
	if json.Unmarshal(data, &entries) != nil || len(entries) > 1024 {
		return nil, ErrPacket
	}
	for _, entry := range entries {
		if !net.ParseIP(entry.Destination).Equal(hop) {
			continue
		}
		mac, err := net.ParseMAC(entry.MAC)
		if err == nil && len(mac) == 6 && mac[0]&1 == 0 && !isZeroMAC(mac) {
			return append(net.HardwareAddr(nil), mac...), nil
		}
	}
	return nil, fmt.Errorf("packet: next-hop neighbor is unresolved")
}

// ResolveRouterMAC consults only the host's route and neighbor tables. If the
// selected on-link next hop is absent, it emits bounded local ARP requests on
// the explicit interface. It never resolves DNS, probes public IP services,
// alters routes/firewall rules, or opens an Internet connection.
func ResolveRouterMAC(ifaceName string, localIP, peerIP net.IP) (net.HardwareAddr, error) {
	if ifaceName == "" || len(ifaceName) > 15 || strings.IndexByte(ifaceName, 0) >= 0 {
		return nil, ErrPacket
	}
	if _, err := ipv4(localIP); err != nil {
		return nil, err
	}
	if _, err := ipv4(peerIP); err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	if len(iface.HardwareAddr) != 6 || iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("packet: active Ethernet interface required")
	}
	routes, err := localIPCommand("-j", "-4", "route", "get", peerIP.To4().String(), "from", localIP.To4().String(), "oif", ifaceName)
	if err != nil {
		return nil, err
	}
	hop, err := routeNextHop(routes, ifaceName, peerIP)
	if err != nil {
		return nil, err
	}
	neighbors, err := localIPCommand("-j", "-4", "neigh", "show", "to", hop.String(), "dev", ifaceName)
	if err == nil {
		if mac, err := neighborMAC(neighbors, hop); err == nil {
			return mac, nil
		}
	}
	return resolveARP(iface, localIP, hop)
}

func arpRequest(localMAC net.HardwareAddr, localIP, hop net.IP) ([]byte, error) {
	local, err := ipv4(localIP)
	if err != nil {
		return nil, err
	}
	target, err := ipv4(hop)
	if err != nil {
		return nil, err
	}
	if len(localMAC) != 6 || localMAC[0]&1 != 0 || isZeroMAC(localMAC) {
		return nil, ErrPacket
	}
	frame := make([]byte, 42)
	for i := 0; i < 6; i++ {
		frame[i] = 255
	}
	copy(frame[6:12], localMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_ARP)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], unix.ETH_P_IP)
	frame[18], frame[19] = 6, 4
	binary.BigEndian.PutUint16(frame[20:22], 1)
	copy(frame[22:28], localMAC)
	copy(frame[28:32], local[:])
	copy(frame[38:42], target[:])
	return frame, nil
}

func arpReplyMAC(frame []byte, localMAC net.HardwareAddr, localIP, hop net.IP) (net.HardwareAddr, error) {
	if len(frame) < 42 || len(localMAC) != 6 || binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_ARP || binary.BigEndian.Uint16(frame[14:16]) != 1 || binary.BigEndian.Uint16(frame[16:18]) != unix.ETH_P_IP || frame[18] != 6 || frame[19] != 4 || binary.BigEndian.Uint16(frame[20:22]) != 2 {
		return nil, ErrPacket
	}
	if !bytes.Equal(frame[:6], localMAC) || !bytes.Equal(frame[32:38], localMAC) || !bytes.Equal(frame[6:12], frame[22:28]) || !net.IP(frame[28:32]).Equal(hop) || !net.IP(frame[38:42]).Equal(localIP) {
		return nil, ErrAdmission
	}
	mac := frame[22:28]
	if mac[0]&1 != 0 || isZeroMAC(mac) {
		return nil, ErrPacket
	}
	return append(net.HardwareAddr(nil), mac...), nil
}

func resolveARP(iface *net.Interface, localIP, hop net.IP) (net.HardwareAddr, error) {
	request, err := arpRequest(iface.HardwareAddr, localIP, hop)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: iface.Index}); err != nil {
		return nil, err
	}
	// Keep the temporary ARP socket scoped to one reply tuple at kernel level.
	var filter []unix.SockFilter
	guard := func(code uint16, off, value uint32) {
		filter = append(filter, unix.SockFilter{Code: code, K: off}, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: value}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 0})
	}
	guard(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 12, unix.ETH_P_ARP)
	guard(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 20, 2)
	guard(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 28, binary.BigEndian.Uint32(hop.To4()))
	guard(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 38, binary.BigEndian.Uint32(localIP.To4()))
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 64})
	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		return nil, err
	}
	destination := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: iface.Index, Halen: 6}
	for i := 0; i < 6; i++ {
		destination.Addr[i] = 255
	}
	deadline := time.Now().Add(3 * time.Second)
	nextSend := time.Time{}
	buffer := make([]byte, 64)
	for time.Now().Before(deadline) {
		if !time.Now().Before(nextSend) {
			if err = unix.Sendto(fd, request, 0, destination); err != nil && err != unix.EINTR && err != unix.EAGAIN && err != unix.EWOULDBLOCK {
				return nil, err
			}
			nextSend = time.Now().Add(time.Second)
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err = unix.Poll(poll, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			continue
		}
		if err != nil {
			return nil, err
		}
		if mac, err := arpReplyMAC(buffer[:n], iface.HardwareAddr, localIP, hop); err == nil {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("packet: local next-hop ARP resolution timed out; set router_mac explicitly")
}
