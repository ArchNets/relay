//go:build linux

// Scoped Linux packet sockets by ir_spoof; https://t.me/ir_spoof.
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var rawIPID atomic.Uint32

func address(ip net.IP, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), ip.To4()...), Port: port}
}

func peerAddress(addr net.Addr, expected *net.UDPAddr) bool {
	udp, ok := addr.(*net.UDPAddr)
	return ok && udp != nil && udp.IP.Equal(expected.IP) && udp.Port == expected.Port && udp.Zone == ""
}

// Listen binds only explicitly configured addresses. Raw carriers need
// CAP_NET_RAW. Ethernet carriers require an explicit interface; the next-hop MAC
// is supplied or resolved locally. Optional capture membership belongs to this
// descriptor. This package does not change shared firewall policy.
func Listen(options Options) (net.PacketConn, error) {
	codec, err := NewCodec(options)
	if err != nil {
		return nil, err
	}
	options = codec.options
	ethernet := options.AFPacket || options.Carrier == "pcap" || options.Carrier == "tcp" || len(options.ReceiveDstIP) != 0 && !options.ReceiveDstIP.Equal(options.LocalIP)
	if !ethernet && (options.PcapPromisc || options.PcapSnaplen != 0 || options.PcapPollMs != 0 || options.PcapFilter != "") {
		return nil, fmt.Errorf("%w: capture options require Ethernet packet I/O", ErrPacket)
	}
	if options.Carrier == "udp" && !ethernet && len(options.SpoofSrcIP) == 0 && len(options.SpoofDstIP) == 0 {
		conn, err := net.ListenUDP("udp4", address(options.LocalIP, options.LocalPort))
		if err != nil {
			return nil, err
		}
		if options.SocketBuffer > 0 {
			if err = conn.SetReadBuffer(options.SocketBuffer); err == nil {
				err = conn.SetWriteBuffer(options.SocketBuffer)
			}
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		return &udpConn{UDPConn: conn, codec: codec, peer: address(options.PeerIP, options.PeerPort)}, nil
	}
	c := &socketConn{codec: codec, fd: -1, readWake: -1, writeWake: -1, ethernet: ethernet, local: address(options.LocalIP, options.LocalPort), peer: address(options.PeerIP, options.PeerPort)}
	c.sequence, c.ack = options.TCPSequence, options.TCPAck
	if options.AllowIPFragments {
		c.fragments = NewReassembler(codec)
	}
	ok := false
	defer func() {
		if !ok {
			c.closeDescriptors()
		}
	}()
	if ethernet {
		if len(options.RouterMAC) == 0 {
			options.RouterMAC, err = ResolveRouterMAC(options.Interface, options.LocalIP, options.PeerIP)
			if err != nil {
				return nil, err
			}
			c.codec.options.RouterMAC = append(net.HardwareAddr(nil), options.RouterMAC...)
		}
		if options.Interface == "" || len(options.RouterMAC) != 6 || options.RouterMAC[0]&1 != 0 || isZeroMAC(options.RouterMAC) {
			return nil, fmt.Errorf("%w: Ethernet carrier requires an interface and unicast next-hop MAC", ErrPacket)
		}
		iface, err := net.InterfaceByName(options.Interface)
		if err != nil {
			return nil, err
		}
		if len(iface.HardwareAddr) != 6 || iface.Flags&net.FlagUp == 0 || options.MTU > iface.MTU {
			return nil, fmt.Errorf("%w: an active Ethernet interface with sufficient MTU is required", ErrPacket)
		}
		c.localMAC = append(net.HardwareAddr(nil), iface.HardwareAddr...)
		c.fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
		if err != nil {
			return nil, err
		}
		sa := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: iface.Index, Halen: 6}
		copy(sa.Addr[:], options.RouterMAC)
		c.destination = sa
		if err = unix.Bind(c.fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: iface.Index}); err != nil {
			return nil, err
		}
		if options.PcapPromisc {
			if err = unix.SetsockoptPacketMreq(c.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{Ifindex: int32(iface.Index), Type: unix.PACKET_MR_PROMISC}); err != nil {
				return nil, err
			}
		}
	} else {
		c.fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(codec.protocol))
		if err != nil {
			return nil, err
		}
		if err = unix.SetsockoptInt(c.fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			return nil, err
		}
		local, _ := ipv4(options.LocalIP)
		if err = unix.Bind(c.fd, &unix.SockaddrInet4{Addr: local}); err != nil {
			return nil, err
		}
		if options.Interface != "" {
			if err = unix.SetsockoptString(c.fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, options.Interface); err != nil {
				return nil, err
			}
		}
		c.destination = &unix.SockaddrInet4{Addr: codec.dst}
	}
	if options.SocketBuffer > 0 {
		if err = unix.SetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_RCVBUF, options.SocketBuffer); err == nil {
			err = unix.SetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, options.SocketBuffer)
		}
		if err != nil {
			return nil, err
		}
	}
	if err = c.attachFilter(); err != nil {
		return nil, err
	}
	c.readWake, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	c.writeWake, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	ok = true
	return c, nil
}

func htons(value uint16) uint16 {
	var wire [2]byte
	binary.BigEndian.PutUint16(wire[:], value)
	return binary.NativeEndian.Uint16(wire[:])
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

// Each descriptor gets an owned, generated BPF filter. It admits only this
// connection's configured wire peer, protocol and optional ports/type/flags.
// Filter lifetime is the socket lifetime; no shared host rule is altered.
func (c *socketConn) socketFilter() []unix.SockFilter {
	var filter []unix.SockFilter
	guard := func(code uint16, offset uint32, value uint32) {
		filter = append(filter, unix.SockFilter{Code: code, K: offset}, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: value}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 0})
	}
	base := uint32(0)
	if c.ethernet {
		if !c.codec.options.PcapPromisc {
			guard(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0, binary.BigEndian.Uint32(c.localMAC[:4]))
			guard(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 4, uint32(binary.BigEndian.Uint16(c.localMAC[4:])))
		}
		guard(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 12, unix.ETH_P_IP)
		base = 14
	}
	guard(unix.BPF_LD|unix.BPF_B|unix.BPF_ABS, base+9, uint32(c.codec.protocol))
	guard(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, base+12, binary.BigEndian.Uint32(c.codec.receiveSrc[:]))
	guard(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, base+16, binary.BigEndian.Uint32(c.codec.receiveDst[:]))
	if c.codec.options.AllowIPFragments {
		// Noninitial fragments have no transport header. Admit them only after
		// the fixed wire-peer/protocol checks; reassembly validates full transport.
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: base + 6},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1, K: 0x1fff},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: uint32(c.captureSize())})
	}
	carrier := c.codec.options.Carrier
	if carrier == "tcp" || carrier == "udp" || carrier == "icmp" {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: base})
	}
	if carrier == "tcp" || carrier == "udp" {
		if !c.codec.options.PeerPortAny {
			guard(unix.BPF_LD|unix.BPF_H|unix.BPF_IND, base, uint32(c.codec.options.PeerPort))
		}
		guard(unix.BPF_LD|unix.BPF_H|unix.BPF_IND, base+2, uint32(c.codec.options.LocalPort))
	}
	if carrier == "tcp" && !c.codec.options.RawTCP {
		guard(unix.BPF_LD|unix.BPF_B|unix.BPF_IND, base+13, uint32(c.codec.options.RemoteFlags))
	}
	if carrier == "tcp" && c.codec.options.RawTCP && len(c.codec.options.RemoteFlagCycle) > 0 {
		cycle := c.codec.options.RemoteFlagCycle
		filter = append(filter, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, K: base + 13})
		for index, flags := range cycle {
			filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: uint8(len(cycle) - index), K: uint32(flags)})
		}
		filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 0})
	}
	if carrier == "icmp" {
		typeValue, codeValue := c.codec.options.ICMPType, c.codec.options.ICMPCode
		if c.codec.options.PeerICMPType != nil {
			typeValue = *c.codec.options.PeerICMPType
		}
		if c.codec.options.PeerICMPCode != nil {
			codeValue = *c.codec.options.PeerICMPCode
		}
		guard(unix.BPF_LD|unix.BPF_B|unix.BPF_IND, base, uint32(typeValue))
		guard(unix.BPF_LD|unix.BPF_B|unix.BPF_IND, base+1, uint32(codeValue))
		if c.codec.options.ICMPIdentifier != nil {
			guard(unix.BPF_LD|unix.BPF_H|unix.BPF_IND, base+4, uint32(*c.codec.options.ICMPIdentifier))
		}
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: uint32(c.captureSize())})
	return filter
}

func (c *socketConn) attachFilter() error {
	filter := c.socketFilter()
	if c.codec.options.PcapFilter != "" {
		custom, err := compileCaptureFilter(c.codec.options.PcapFilter, c.captureSize())
		if err != nil {
			return err
		}
		filter, err = combineCaptureFilters(custom, filter)
		if err != nil {
			return err
		}
	}
	return unix.SetsockoptSockFprog(c.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]})
}

type udpConn struct {
	*net.UDPConn
	codec  *Codec
	peer   *net.UDPAddr
	readMu sync.Mutex
}

func (c *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	buffer := make([]byte, c.codec.PayloadMTU()+1)
	for {
		n, addr, err := c.UDPConn.ReadFromUDP(buffer)
		if err != nil {
			return 0, nil, err
		}
		wirePeer := address(net.IP(c.codec.receiveSrc[:]), c.peer.Port)
		if n > c.codec.PayloadMTU() || !peerAddress(addr, wirePeer) {
			continue
		}
		return copy(p, buffer[:n]), address(c.peer.IP, c.peer.Port), nil
	}
}

func (c *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !peerAddress(addr, c.peer) {
		return 0, ErrAdmission
	}
	if len(p) > c.codec.PayloadMTU() {
		return 0, ErrMTU
	}
	return c.UDPConn.WriteToUDP(p, c.peer)
}

type socketConn struct {
	codec                       *Codec
	fragments                   *Reassembler
	fd, readWake, writeWake     int
	ethernet                    bool
	localMAC                    net.HardwareAddr
	destination                 unix.Sockaddr
	local, peer                 *net.UDPAddr
	readMu, writeMu             sync.Mutex
	stateMu                     sync.Mutex
	closed                      bool
	readDeadline, writeDeadline time.Time
	packetID                    uint16
	sequence, ack               uint32
	// Listener state is scoped to the configured peer's source port. The
	// uint16 keyspace bounds memory; entries exist only after successful encoding.
	rawPeers  map[uint16]rawTCPState
	closeOnce sync.Once
	closeErr  error
}

type rawTCPState struct{ sequence, ack uint32 }

func (c *socketConn) opError(op string, err error) error {
	return &net.OpError{Op: op, Net: "ipv4-carrier", Addr: c.local, Err: err}
}

func (c *socketConn) state(write bool) (bool, time.Time) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if write {
		return c.closed, c.writeDeadline
	}
	return c.closed, c.readDeadline
}

func notify(fd int) {
	var value [8]byte
	binary.NativeEndian.PutUint64(value[:], 1)
	for {
		_, err := unix.Write(fd, value[:])
		if err != unix.EINTR {
			return
		}
	}
}

func drain(fd int) {
	var value [8]byte
	for {
		_, err := unix.Read(fd, value[:])
		if err != unix.EINTR {
			return
		}
	}
}

// Separate wake descriptors ensure a deadline update or close wakes both read
// and write without either operation consuming the other's notification.
func (c *socketConn) wait(write bool) error {
	wake, event := c.readWake, int16(unix.POLLIN)
	if write {
		wake, event = c.writeWake, unix.POLLOUT
	}
	for {
		closed, deadline := c.state(write)
		if closed {
			return net.ErrClosed
		}
		timeout := -1
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return os.ErrDeadlineExceeded
			}
			milliseconds := remaining / time.Millisecond
			if remaining%time.Millisecond != 0 {
				milliseconds++
			}
			if milliseconds > 1<<31-1 {
				milliseconds = 1<<31 - 1
			}
			timeout = int(milliseconds)
		}
		if !write && c.codec.options.PcapPollMs > 0 && (timeout < 0 || timeout > c.codec.options.PcapPollMs) {
			timeout = c.codec.options.PcapPollMs
		}
		fds := []unix.PollFd{{Fd: int32(c.fd), Events: event}, {Fd: int32(wake), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, timeout)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if fds[1].Revents != 0 {
			drain(wake)
			continue
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return net.ErrClosed
		}
		if fds[0].Revents&(event|unix.POLLERR|unix.POLLHUP) != 0 {
			return nil
		}
	}
}

func (c *socketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	buffer := make([]byte, c.captureSize())
	for {
		if err := c.wait(false); err != nil {
			return 0, nil, c.opError("read", err)
		}
		n, _, err := unix.Recvfrom(c.fd, buffer, unix.MSG_TRUNC)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, nil, c.opError("read", err)
		}
		if n > len(buffer) {
			continue
		}
		frame := buffer[:n]
		if c.ethernet {
			localMAC := c.localMAC
			if c.codec.options.PcapPromisc {
				if len(frame) < 6 {
					continue
				}
				localMAC = frame[:6]
			}
			frame, err = DecodeEthernet(localMAC, frame)
			if err != nil {
				continue
			}
		}
		if c.fragments != nil {
			frame, err = c.fragments.Assemble(frame, time.Now())
			if err != nil {
				continue
			}
		}
		payload, peer, err := c.codec.DecodePeer(frame)
		if err != nil {
			continue
		}
		return copy(p, payload), peer, nil
	}
}

func (c *socketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	peer, ok := addr.(*net.UDPAddr)
	if !ok || peer == nil || !peer.IP.Equal(c.peer.IP) || peer.Zone != "" || peer.Port < 0 || peer.Port > 65535 || (c.codec.options.Carrier == "tcp" || c.codec.options.Carrier == "udp") && peer.Port == 0 || !c.codec.options.PeerPortAny && peer.Port != c.peer.Port {
		return 0, ErrAdmission
	}
	closed, deadline := c.state(true)
	if closed {
		return 0, c.opError("write", net.ErrClosed)
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, c.opError("write", os.ErrDeadlineExceeded)
	}
	id := c.packetID
	codec := c.codec
	if codec.options.PeerPortAny {
		copyCodec := *codec
		copyCodec.options.PeerPort = peer.Port
		codec = &copyCodec
	}
	var frame []byte
	var err error
	sequence, ack := c.sequence, c.ack
	if codec.options.RawTCP && codec.options.PeerPortAny {
		if state, exists := c.rawPeers[uint16(peer.Port)]; exists {
			sequence, ack = state.sequence, state.ack
		} else {
			sequence, ack = codec.options.TCPSequence, codec.options.TCPAck
		}
	}
	if c.codec.options.RawTCP {
		id = uint16(rawIPID.Add(1))
		frame, err = codec.EncodeTCP(p, id, sequence, ack, codec.tcpFlags(sequence))
	} else {
		frame, err = codec.Encode(p, id)
	}
	if err != nil {
		return 0, err
	}
	c.packetID++
	if c.codec.options.RawTCP {
		if codec.options.PeerPortAny {
			if c.rawPeers == nil {
				c.rawPeers = make(map[uint16]rawTCPState)
			}
			c.rawPeers[uint16(peer.Port)] = rawTCPState{sequence: sequence + uint32(len(p)+8), ack: ack}
		} else {
			c.sequence += uint32(len(p) + 8)
		}
	}
	frames := [][]byte{frame}
	if c.codec.options.AllowIPFragments {
		frames, err = FragmentIPv4(frame, c.codec.options.MTU)
		if err != nil {
			return 0, err
		}
	}
	for _, frame = range frames {
		if c.ethernet {
			frame, err = EncodeEthernet(c.localMAC, c.codec.options.RouterMAC, frame)
			if err != nil {
				return 0, err
			}
		}
		for {
			closed, deadline = c.state(true)
			if closed {
				return 0, c.opError("write", net.ErrClosed)
			}
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return 0, c.opError("write", os.ErrDeadlineExceeded)
			}
			err = unix.Sendto(c.fd, frame, 0, c.destination)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				if err = c.wait(true); err != nil {
					return 0, c.opError("write", err)
				}
				continue
			}
			if err == unix.EMSGSIZE {
				err = ErrMTU
			}
			if err != nil {
				return 0, c.opError("write", err)
			}
			break
		}
	}
	return len(p), nil
}

func (c *socketConn) captureSize() int {
	if c.codec.options.PcapSnaplen > 0 {
		return c.codec.options.PcapSnaplen
	}
	if c.codec.options.AllowIPFragments && !c.ethernet {
		return 65535 + 64
	}
	return c.codec.options.MTU + 64
}

func (c *socketConn) LocalAddr() net.Addr { return address(c.local.IP, c.local.Port) }

// KCP probes these optional buffer setters through its PacketConn. Holding the
// state lock prevents descriptor closure during the short setsockopt syscall.
func (c *socketConn) setBuffer(option, size int) error {
	if size < 1 || size > 64<<20 {
		return ErrPacket
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	return unix.SetsockoptInt(c.fd, unix.SOL_SOCKET, option, size)
}

func (c *socketConn) SetReadBuffer(size int) error  { return c.setBuffer(unix.SO_RCVBUF, size) }
func (c *socketConn) SetWriteBuffer(size int) error { return c.setBuffer(unix.SO_SNDBUF, size) }

func (c *socketConn) SetDeadline(deadline time.Time) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline, c.writeDeadline = deadline, deadline
	notify(c.readWake)
	notify(c.writeWake)
	return nil
}

func (c *socketConn) SetReadDeadline(deadline time.Time) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline = deadline
	notify(c.readWake)
	return nil
}

func (c *socketConn) SetWriteDeadline(deadline time.Time) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDeadline = deadline
	notify(c.writeWake)
	return nil
}

func (c *socketConn) closeDescriptors() {
	for _, fd := range []int{c.fd, c.readWake, c.writeWake} {
		if fd >= 0 {
			if err := unix.Close(fd); err != nil && !errors.Is(err, unix.EBADF) && c.closeErr == nil {
				c.closeErr = err
			}
		}
	}
}

func (c *socketConn) Close() error {
	c.closeOnce.Do(func() {
		c.stateMu.Lock()
		c.closed = true
		notify(c.readWake)
		notify(c.writeWake)
		c.stateMu.Unlock()
		// Waiting for operations prevents closing and recycling an fd while an
		// in-flight operation could still issue a syscall on that descriptor.
		c.readMu.Lock()
		defer c.readMu.Unlock()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.closeDescriptors()
	})
	return c.closeErr
}
