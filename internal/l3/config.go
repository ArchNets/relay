// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"netrix.local/ir_spoof/internal/config"
	"netrix.local/ir_spoof/internal/firewall"
	"netrix.local/ir_spoof/internal/packet"
)

type settings struct {
	scope                                             Scope
	packet                                            packet.Options
	name, local, peer                                 string
	mtu, queues, fragmentSize, channelSize, batchSize int
	routes                                            []string
	interval, timeout                                 time.Duration
	readBuffer, writeBuffer, healthPort               int
	mappings                                          []config.Mapping
	forward                                           *firewall.Options
}

var validTUNName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)

func literalIPv4(value string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return nil
	}
	return ip.To4()
}

// Validate checks the complete standalone L3 configuration without creating
// interfaces, network sockets or making discovery requests.
func Validate(c *config.Config) error {
	_, err := loadSettings(c)
	return err
}

func loadSettings(c *config.Config) (*settings, error) {
	if c == nil || c.Transport != "l3" || c.L3 == nil || c.Tun == nil || !c.Tun.Enabled {
		return nil, errors.New("l3: transport requires l3 settings and an enabled TUN interface")
	}
	if c.Mode != "server" && c.Mode != "client" {
		return nil, errors.New("l3: mode must be server or client")
	}
	l, t := c.L3, c.Tun
	s := &settings{name: t.Name, local: t.Local, peer: t.Remote, mtu: t.MTU, queues: t.Streams, routes: append([]string(nil), t.Routes...), fragmentSize: l.FragmentSize, channelSize: l.ChannelSize, batchSize: l.BatchSize, readBuffer: l.SoRcvbuf, writeBuffer: l.SoSndbuf, healthPort: t.HealthPort}
	if s.name == "" {
		s.name = "netrixl3"
	}
	if s.mtu == 0 {
		s.mtu = 1320
	}
	if s.queues == 0 {
		s.queues = 1
	}
	profile := strings.ToLower(strings.TrimSpace(l.Profile))
	channel, batch := 15000, 1024
	switch profile {
	case "", "balanced":
	case "aggressive":
		channel, batch = 32768, 4096
	case "latency":
		channel, batch = 2048, 1
	case "cpu-efficient":
		channel, batch = 8192, 2048
	default:
		return nil, errors.New("l3: unknown runtime profile")
	}
	if s.channelSize == 0 {
		s.channelSize = channel
	}
	if s.batchSize == 0 {
		s.batchSize = batch
	}
	if c.HealthPort != 0 {
		s.healthPort = c.HealthPort
	}
	if !validTUNName.MatchString(s.name) || s.queues < 1 || s.queues > 64 || s.mtu < 576 || s.mtu > MaximumPayload {
		return nil, errors.New("l3: invalid TUN name, queue count or MTU")
	}
	local, err := netip.ParsePrefix(s.local)
	if err != nil || local.Addr().IsUnspecified() || local.Addr().IsMulticast() || local.Addr().Is4In6() {
		return nil, errors.New("l3: tun.local must be a literal IP/prefix")
	}
	peer, err := netip.ParseAddr(s.peer)
	if err != nil {
		if prefix, prefixErr := netip.ParsePrefix(s.peer); prefixErr == nil {
			peer = prefix.Addr()
			err = nil
		}
	}
	if err != nil || peer.IsUnspecified() || peer.IsMulticast() || peer.Is4In6() || peer.Is4() != local.Addr().Is4() || peer == local.Addr() {
		return nil, errors.New("l3: tun.remote must be a distinct literal IP or IP/prefix of the same family")
	}
	if local.Addr().Is6() && s.mtu < 1280 {
		return nil, errors.New("l3: IPv6 TUN MTU must be at least 1280")
	}
	for _, route := range s.routes {
		if _, err := netip.ParsePrefix(route); err != nil {
			return nil, errors.New("l3: invalid route prefix")
		}
	}
	if s.channelSize < 1 || s.channelSize > 65536 || s.batchSize < 1 || s.batchSize > 524288 || s.healthPort < 0 || s.healthPort > 65535 || s.readBuffer < 0 || s.writeBuffer < 0 || s.readBuffer > 64<<20 || s.writeBuffer > 64<<20 {
		return nil, errors.New("l3: queue, batch, health or socket-buffer bound exceeded")
	}
	if s.fragmentSize != 0 && (s.fragmentSize < 256 || s.fragmentSize > MaximumPayload-FragmentHeaderSize) {
		return nil, errors.New("l3: fragment_size must be zero or 256..65527")
	}
	if t.ForwardL2TP {
		options := firewall.Options{Interface: s.name, LocalCIDR: s.local, Remote: s.peer, Ports: t.L2TPPorts, Destination: t.L2TPDestIP}
		if err := firewall.Validate(options); err != nil {
			return nil, err
		}
		s.forward = &options
	} else if len(t.L2TPPorts) != 0 || t.L2TPDestIP != "" {
		return nil, errors.New("l3: L2TP port/destination settings require forward_l2tp=true")
	}
	if len(c.Paths) != 0 || c.Direct {
		return nil, errors.New("l3: multipath or direct-role reversal is not supported by this standalone carrier")
	}
	// The reference parses TUN endpoints before deriving SID/KDF contexts;
	// prefix lengths configure the device but are absent from the wire scope.
	s.scope = Scope{Carrier: strings.ToLower(strings.TrimSpace(l.Carrier)), LocalIP: l.ListenIP, PeerIP: l.DstIP, SpoofSrcIP: l.SpoofSrcIP, SpoofDstIP: l.SpoofDstIP, LocalPort: l.ListenPort, PeerPort: l.DstPort, ICMPType: l.ICMPType, ICMPCode: l.ICMPCode, TUNLocal: local.Addr().String(), TUNRemote: peer.String(), Encrypted: true, Algorithm: l.Algorithm, PSK: l.PSK, Iterations: l.KDFIterations}
	if s.scope.Carrier == "" {
		s.scope.Carrier = "raw"
	}
	if l.EnableEncryption != nil {
		s.scope.Encrypted = *l.EnableEncryption
	}
	if s.scope.PSK == "" {
		s.scope.PSK = c.PSK
	}
	if s.scope.LocalPort == 0 {
		s.scope.LocalPort = 40001
	}
	if s.scope.PeerPort == 0 {
		s.scope.PeerPort = s.scope.LocalPort
	}
	if l.HeartbeatInterval < 0 || l.HeartbeatTimeout < 0 {
		return nil, errors.New("l3: heartbeat durations must be positive")
	}
	s.interval = time.Duration(l.HeartbeatInterval) * time.Second
	if s.interval == 0 {
		s.interval = 5 * time.Second
	}
	s.timeout = time.Duration(l.HeartbeatTimeout) * time.Second
	if s.timeout == 0 {
		s.timeout = 30 * time.Second
	}
	if s.interval > time.Hour || s.timeout <= s.interval || s.timeout > 24*time.Hour {
		return nil, errors.New("l3: heartbeat timeout must exceed interval, within bounded durations")
	}
	src, dst := literalIPv4(s.scope.LocalIP), literalIPv4(s.scope.PeerIP)
	if src == nil || dst == nil {
		return nil, errors.New("l3: listen_ip and dst_ip must be explicit unicast IPv4 addresses")
	}
	if (s.scope.SpoofSrcIP != "") != (s.scope.SpoofDstIP != "") {
		return nil, errors.New("l3: provide both spoof_src_ip and spoof_dst_ip")
	}
	s.packet = packet.Options{Carrier: s.scope.Carrier, Interface: l.Interface, LocalIP: src, PeerIP: dst, LocalPort: s.scope.LocalPort, PeerPort: s.scope.PeerPort, ICMPType: uint8(l.ICMPType), ICMPCode: uint8(l.ICMPCode), MTU: 1500, SocketBuffer: max(l.SoSndbuf, l.SoRcvbuf)}
	if s.scope.Carrier == "raw" {
		s.packet.Protocol = 58
	}
	if s.scope.Carrier == "icmp" && (l.ICMPType < 0 || l.ICMPType > 255 || l.ICMPCode < 0 || l.ICMPCode > 255) {
		return nil, errors.New("l3: invalid ICMP type/code")
	}
	if s.scope.Carrier == "icmp" {
		sid, err := s.scope.SessionID()
		if err != nil {
			return nil, err
		}
		identifier := icmpIdentifier(sid)
		s.packet.ICMPIdentifier = &identifier
	}
	if s.scope.Carrier == "pcap" {
		s.packet.Carrier = "udp"
		s.packet.AFPacket = true
	}
	if l.AFPacketTX != nil && *l.AFPacketTX {
		s.packet.AFPacket = true
	}
	if l.AllowIPFrag != nil && *l.AllowIPFrag {
		if s.packet.Carrier != "raw" && s.packet.Carrier != "icmp" {
			return nil, errors.New("l3: allow_ip_frag applies only to raw or ICMP carriers; UDP retains DF and TCP is a stream")
		}
		s.packet.AllowIPFragments = true
	}
	if l.PcapFilter != "" || l.PcapSnaplen != 0 || l.PcapPollMs != 0 || l.PcapPromisc != nil && *l.PcapPromisc {
		if !s.packet.AFPacket {
			return nil, errors.New("l3: capture tuning requires pcap carrier or af_packet_tx=true")
		}
		s.packet.PcapFilter = l.PcapFilter
		s.packet.PcapSnaplen = l.PcapSnaplen
		s.packet.PcapPollMs = l.PcapPollMs
		s.packet.PcapPromisc = l.PcapPromisc != nil && *l.PcapPromisc
	}
	if s.scope.SpoofSrcIP != "" {
		if s.scope.Carrier == "tcp" {
			return nil, errors.New("l3: real TCP stream carrier cannot spoof its IP addresses")
		}
		s.packet.SpoofSrcIP = literalIPv4(s.scope.SpoofSrcIP)
		peerSource := literalIPv4(s.scope.SpoofDstIP)
		if s.packet.SpoofSrcIP == nil || peerSource == nil {
			return nil, errors.New("l3: spoof addresses must be explicit unicast IPv4")
		}
		// Recovered L3 applies source spoofing on transmission to the real peer.
		// spoof_dst_ip identifies that peer's expected spoofed source, while the
		// destination admitted on receive remains the configured local address.
		s.packet.ReceiveSrcIP = peerSource
		s.packet.ReceiveDstIP = src
	}
	if c.Rawsocket != nil && c.Rawsocket.RouterMac != "" {
		s.packet.RouterMAC, err = net.ParseMAC(c.Rawsocket.RouterMac)
		if err != nil {
			return nil, errors.New("l3: invalid explicit next-hop MAC")
		}
	}
	if s.packet.AFPacket || s.packet.ReceiveDstIP != nil && !s.packet.ReceiveDstIP.Equal(s.packet.LocalIP) {
		if l.Interface == "" {
			return nil, errors.New("l3: AF_PACKET/pcap/spoof reception requires an explicit interface")
		}
	}
	if s.scope.Carrier == "tcp" {
		if s.packet.AFPacket || s.scope.LocalPort < 1 || s.scope.LocalPort > 65535 || s.scope.PeerPort < 1 || s.scope.PeerPort > 65535 {
			return nil, errors.New("l3: TCP needs valid ports and an ordinary stream socket")
		}
	} else {
		if _, err := packet.NewCodec(s.packet); err != nil {
			return nil, fmt.Errorf("l3: carrier options: %w", err)
		}
	}
	if _, err := s.scope.SessionID(); err != nil {
		return nil, err
	}
	if s.scope.Encrypted && (s.scope.Iterations < 0 || s.scope.Iterations > MaximumIterations) {
		return nil, errors.New("l3: KDF work limit exceeded")
	}
	if s.scope.Carrier != "tcp" {
		overhead := 20 + HeaderSize
		if s.packet.Carrier == "icmp" || s.packet.Carrier == "udp" {
			overhead += 8
		}
		if s.scope.Encrypted {
			overhead += 28
		}
		part := s.mtu
		if s.fragmentSize > 0 && part > s.fragmentSize {
			part = s.fragmentSize + FragmentHeaderSize
		}
		maximum := s.packet.MTU
		if s.packet.AllowIPFragments {
			maximum = 65535
		}
		if part+overhead > maximum {
			return nil, errors.New("l3: TUN packet exceeds outer IPv4 length/MTU; reduce tun.mtu or fragment_size")
		}
	}
	if c.Mode == "server" {
		s.mappings, err = l3Mappings(c, peer.String())
		if err != nil {
			return nil, err
		}
	} else if len(c.Maps) != 0 || len(c.TCPPorts) != 0 || len(c.UDPPorts) != 0 {
		return nil, errors.New("l3: listener mappings belong on server mode")
	}
	return s, nil
}

// The reference folds its stable SID into the outer ICMP identifier. A zero
// fold uses the recovered nonzero sentinel; type/code admission is independent.
func icmpIdentifier(sid uint32) uint16 {
	identifier := uint16(sid ^ (sid >> 16))
	if identifier == 0 {
		return 0x4e45
	}
	return identifier
}

// The upstream manager documents remote TUN address as the default destination
// for simple L3 port entries. Explicit target addresses remain explicit.
func l3Mappings(c *config.Config, remote string) ([]config.Mapping, error) {
	out := append([]config.Mapping(nil), c.Maps...)
	for _, group := range []struct {
		kind  string
		items []any
	}{{"tcp", c.TCPPorts}, {"udp", c.UDPPorts}} {
		for _, item := range group.items {
			clone := config.Config{}
			if group.kind == "tcp" {
				clone.TCPPorts = []any{item}
			} else {
				clone.UDPPorts = []any{item}
			}
			rows, err := clone.Mappings()
			if err != nil {
				return nil, err
			}
			text := fmt.Sprint(item)
			fields, depth := []string{}, 0
			start := 0
			for i, ch := range text {
				if ch == '[' {
					depth++
				}
				if ch == ']' {
					depth--
				}
				if ch == ':' && depth == 0 {
					fields = append(fields, text[start:i])
					start = i + 1
				}
			}
			fields = append(fields, text[start:])
			defaultTarget := !strings.Contains(text, "=") && !strings.Contains(text, "->") && (len(fields) <= 2 || len(fields) == 3 && literalIPv4(fields[0]) != nil)
			if defaultTarget {
				for i := range rows {
					_, port, _ := net.SplitHostPort(rows[i].Target)
					rows[i].Target = net.JoinHostPort(remote, port)
				}
			}
			out = append(out, rows...)
		}
	}
	if len(out) > 4096 {
		return nil, errors.New("l3: too many listener mappings")
	}
	seen := make(map[string]bool)
	for _, row := range out {
		bindHost, _, err := net.SplitHostPort(row.Bind)
		if err != nil || bindHost != "" && net.ParseIP(bindHost) == nil {
			return nil, errors.New("l3: mapping bind must be a literal local endpoint")
		}
		targetHost, _, err := net.SplitHostPort(row.Target)
		if err != nil || net.ParseIP(targetHost) == nil {
			return nil, errors.New("l3: mapping target must be a literal IP endpoint")
		}
		if row.Type != "tcp" && row.Type != "udp" || seen[row.Type+"/"+row.Bind] {
			return nil, errors.New("l3: invalid or duplicate listener mapping")
		}
		seen[row.Type+"/"+row.Bind] = true
	}
	return out, nil
}
