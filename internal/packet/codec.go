// Independent Linux carrier reconstruction by ir_spoof; https://t.me/ir_spoof.
// Package packet wraps opaque datagrams in bounded IPv4 carriers. These codecs
// do not define the reference application's inner KCP or L3 payload protocol.
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	TCPFIN = uint8(0x01)
	TCPSYN = uint8(0x02)
	TCPRST = uint8(0x04)
	TCPPSH = uint8(0x08)
	TCPACK = uint8(0x10)
	TCPURG = uint8(0x20)
	TCPECE = uint8(0x40)
	TCPCWR = uint8(0x80)
)

var (
	ErrPacket    = errors.New("packet: malformed or unsupported frame")
	ErrAdmission = errors.New("packet: frame does not match configured peer")
	ErrMTU       = errors.New("packet: datagram exceeds carrier MTU")
	ErrPlatform  = errors.New("packet: carrier requires Linux")
)

// Options uses literal IPv4 addresses only. Spoof addresses affect transmission;
// receive overrides admit the configured peer's wire addresses independently.
// RouterMAC fixes the next-hop MAC when supplied; otherwise Linux resolves it
// from the configured local interface, route, neighbor table or scoped ARP.
type Options struct {
	Carrier                    string
	Interface                  string
	LocalIP, PeerIP            net.IP
	SpoofSrcIP, SpoofDstIP     net.IP
	ReceiveSrcIP, ReceiveDstIP net.IP
	LocalPort, PeerPort        int
	// PeerPortAny is an explicit RawTCP listener-only wildcard. The peer IP
	// remains fixed; replies must use the validated address returned by ReadFrom.
	PeerPortAny             bool
	Protocol                uint8
	LocalFlags, RemoteFlags uint8
	// RawTCP enables the recovered reference rawsocket's eight-byte envelope.
	// It is distinct from an opaque generic TCP-shaped L3 datagram.
	RawTCP bool
	// Zero initial state selects the recovered constructor's sequence/ACK of 1.
	// EncodeTCP can explicitly encode sequence zero for an offline fixture.
	TCPSequence, TCPAck             uint32
	LocalFlagCycle, RemoteFlagCycle []uint8
	ICMPType, ICMPCode              uint8
	PeerICMPType, PeerICMPCode      *uint8
	// ICMPIdentifier sets the common transmit/receive identifier when present.
	// Without an override, generic callers retain the local-port wire value.
	ICMPIdentifier *uint16
	RouterMAC      net.HardwareAddr
	MTU            int
	SocketBuffer   int
	// AllowIPFragments clears DF and enables bounded fragment I/O for raw/ICMP.
	// UDP retains the recovered carrier's DF flag and does not fragment here.
	AllowIPFragments bool
	// AFPacket requests Ethernet-layer I/O even for raw or ICMP carriers.
	AFPacket bool
	// Optional Ethernet capture settings affect only this owned packet socket.
	PcapSnaplen int
	PcapPollMs  int
	PcapPromisc bool
	// PcapFilter is compiled offline by trusted system libpcap or tcpdump; its
	// condition is combined with the fixed peer admission filter.
	PcapFilter string
}

type Codec struct {
	options                          Options
	src, dst, receiveSrc, receiveDst [4]byte
	protocol                         uint8
	headerSize                       int
}

func ipv4(ip net.IP) ([4]byte, error) {
	var value [4]byte
	v := ip.To4()
	if v == nil || v.IsUnspecified() || v.IsMulticast() || v.Equal(net.IPv4bcast) {
		return value, fmt.Errorf("%w: literal unicast IPv4 address required", ErrPacket)
	}
	copy(value[:], v)
	return value, nil
}

func NewCodec(options Options) (*Codec, error) {
	// Caller-owned slices and optional bytes must not mutate a live admission rule.
	options.LocalIP = append(net.IP(nil), options.LocalIP...)
	options.PeerIP = append(net.IP(nil), options.PeerIP...)
	options.SpoofSrcIP = append(net.IP(nil), options.SpoofSrcIP...)
	options.SpoofDstIP = append(net.IP(nil), options.SpoofDstIP...)
	options.ReceiveSrcIP = append(net.IP(nil), options.ReceiveSrcIP...)
	options.ReceiveDstIP = append(net.IP(nil), options.ReceiveDstIP...)
	options.RouterMAC = append(net.HardwareAddr(nil), options.RouterMAC...)
	options.LocalFlagCycle = append([]uint8(nil), options.LocalFlagCycle...)
	options.RemoteFlagCycle = append([]uint8(nil), options.RemoteFlagCycle...)
	if options.PeerICMPType != nil {
		value := *options.PeerICMPType
		options.PeerICMPType = &value
	}
	if options.PeerICMPCode != nil {
		value := *options.PeerICMPCode
		options.PeerICMPCode = &value
	}
	if options.ICMPIdentifier != nil {
		value := *options.ICMPIdentifier
		options.ICMPIdentifier = &value
	}
	options.Carrier = strings.ToLower(options.Carrier)
	if options.Carrier == "" {
		options.Carrier = "raw"
	}
	if options.MTU == 0 {
		options.MTU = 1500
	}
	if options.RawTCP {
		if options.TCPSequence == 0 {
			options.TCPSequence = 1
		}
		if options.TCPAck == 0 {
			options.TCPAck = 1
		}
		if len(options.LocalFlagCycle) == 0 && options.LocalFlags == 0 {
			options.LocalFlagCycle = []uint8{TCPPSH | TCPACK}
			if !options.PeerPortAny {
				options.LocalFlagCycle = append(options.LocalFlagCycle, TCPACK)
			}
		}
	}
	if options.MTU < 68 || options.MTU > 65535 || options.LocalPort < 0 || options.LocalPort > 65535 || options.PeerPort < 0 || options.PeerPort > 65535 || options.SocketBuffer < 0 || options.SocketBuffer > 64<<20 || len(options.Interface) > 15 || strings.IndexByte(options.Interface, 0) >= 0 || len(options.LocalFlagCycle) > 32 || len(options.RemoteFlagCycle) > 32 || options.RawTCP && options.Carrier != "tcp" || options.PeerPortAny && (!options.RawTCP || options.Carrier != "tcp" || options.PeerPort != 0) {
		return nil, ErrPacket
	}
	if options.PcapSnaplen != 0 && (options.PcapSnaplen < 68 || options.PcapSnaplen > 262144) || options.PcapPollMs < 0 || options.PcapPollMs > 60000 || len(options.PcapFilter) > 4096 || strings.IndexByte(options.PcapFilter, 0) >= 0 {
		return nil, ErrPacket
	}
	c := &Codec{options: options, headerSize: 20}
	var expected uint8
	switch options.Carrier {
	case "raw", "pcap":
		c.protocol = options.Protocol
		if c.protocol == 0 {
			c.protocol = 253
		}
	case "icmp":
		expected = 1
		c.headerSize += 8
	case "udp":
		expected = 17
		c.headerSize += 8
		if options.LocalPort == 0 || options.PeerPort == 0 {
			return nil, fmt.Errorf("%w: UDP ports are required", ErrPacket)
		}
	case "tcp":
		expected = 6
		c.headerSize += 20
		if options.LocalPort == 0 || options.PeerPort == 0 && !options.PeerPortAny {
			return nil, fmt.Errorf("%w: TCP-shaped carrier ports are required", ErrPacket)
		}
		if options.RawTCP {
			c.headerSize += 8
		}
	default:
		return nil, fmt.Errorf("%w: unsupported carrier", ErrPacket)
	}
	if options.AllowIPFragments && (options.Carrier != "raw" && options.Carrier != "pcap" && options.Carrier != "icmp" || options.RawTCP) {
		return nil, fmt.Errorf("%w: fragmentation is supported for raw-IP and ICMP carriers", ErrPacket)
	}
	if expected != 0 {
		if options.Protocol != 0 && options.Protocol != expected {
			return nil, ErrPacket
		}
		c.protocol = expected
	}
	src, dst := options.LocalIP, options.PeerIP
	if len(options.SpoofSrcIP) != 0 {
		src = options.SpoofSrcIP
	}
	if len(options.SpoofDstIP) != 0 {
		dst = options.SpoofDstIP
	}
	receiveSrc, receiveDst := options.PeerIP, options.LocalIP
	if len(options.ReceiveSrcIP) != 0 {
		receiveSrc = options.ReceiveSrcIP
	}
	if len(options.ReceiveDstIP) != 0 {
		receiveDst = options.ReceiveDstIP
	}
	var err error
	if _, err = ipv4(options.LocalIP); err != nil {
		return nil, err
	}
	if _, err = ipv4(options.PeerIP); err != nil {
		return nil, err
	}
	if c.src, err = ipv4(src); err != nil {
		return nil, err
	}
	if c.dst, err = ipv4(dst); err != nil {
		return nil, err
	}
	if c.receiveSrc, err = ipv4(receiveSrc); err != nil {
		return nil, err
	}
	if c.receiveDst, err = ipv4(receiveDst); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Codec) PayloadMTU() int { return c.options.MTU - c.headerSize }

// MaxPayload includes bounded IPv4 fragmentation where explicitly enabled.
func (c *Codec) MaxPayload() int {
	if c.options.AllowIPFragments {
		return 65535 - c.headerSize
	}
	return c.PayloadMTU()
}

func PeerAddr(options Options) (net.Addr, error) {
	c, err := NewCodec(options)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: append(net.IP(nil), c.options.PeerIP.To4()...), Port: c.options.PeerPort}, nil
}

func (c *Codec) tcpFlags(sequence uint32) uint8 {
	if c.options.RawTCP {
		if len(c.options.LocalFlagCycle) > 0 {
			return c.options.LocalFlagCycle[uint64(sequence)%uint64(len(c.options.LocalFlagCycle))]
		}
		if c.options.LocalFlags == 0 {
			return TCPPSH | TCPACK
		}
	}
	return c.options.LocalFlags
}

func (c *Codec) admitTCPFlags(flags uint8) bool {
	if !c.options.RawTCP {
		return flags == c.options.RemoteFlags
	}
	if len(c.options.RemoteFlagCycle) == 0 {
		return true
	}
	for _, allowed := range c.options.RemoteFlagCycle {
		if flags == allowed {
			return true
		}
	}
	return false
}

// Checksum is the standard Internet one's-complement checksum. It accepts odd
// lengths without reading beyond the supplied slice.
func Checksum(data []byte) uint16 {
	var sum uint64
	for len(data) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint64(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func transportChecksum(src, dst [4]byte, protocol uint8, data []byte) uint16 {
	pseudo := make([]byte, 12+len(data))
	copy(pseudo[:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(data)))
	copy(pseudo[12:], data)
	return Checksum(pseudo)
}

// Encode returns an IPv4 datagram. TCP is a shaped datagram header, not a TCP
// stream, handshake, acknowledgement engine, or congestion-control protocol.
func (c *Codec) Encode(payload []byte, id uint16) ([]byte, error) {
	sequence, ack := uint32(id), uint32(0)
	if c.options.RawTCP {
		sequence, ack = c.options.TCPSequence, c.options.TCPAck
	}
	return c.EncodeTCP(payload, id, sequence, ack, c.tcpFlags(sequence))
}

// EncodeTCP supplies explicit sequence/acknowledgement state for a TCP-shaped
// datagram. Other carriers ignore those fields. RawTCP payload length and TCP
// sequence progression are recovered separately from the generic carrier.
func (c *Codec) EncodeTCP(payload []byte, id uint16, sequence, ack uint32, flags uint8) ([]byte, error) {
	if c.options.PeerPortAny && c.options.PeerPort == 0 {
		return nil, ErrAdmission
	}
	if len(payload) > c.MaxPayload() {
		return nil, ErrMTU
	}
	if c.options.RawTCP && len(payload) == 0 {
		return nil, ErrPacket
	}
	frame := make([]byte, c.headerSize+len(payload))
	frame[0] = 0x45
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	binary.BigEndian.PutUint16(frame[4:6], id)
	if !c.options.RawTCP && !c.options.AllowIPFragments {
		binary.BigEndian.PutUint16(frame[6:8], 0x4000)
	} // Reference rawsocket leaves this field zero.
	frame[8], frame[9] = 64, c.protocol
	copy(frame[12:16], c.src[:])
	copy(frame[16:20], c.dst[:])
	body := frame[20:]
	switch c.options.Carrier {
	case "icmp":
		body[0], body[1] = c.options.ICMPType, c.options.ICMPCode
		identifier := uint16(c.options.LocalPort)
		if c.options.ICMPIdentifier != nil {
			identifier = *c.options.ICMPIdentifier
		}
		binary.BigEndian.PutUint16(body[4:6], identifier)
		binary.BigEndian.PutUint16(body[6:8], id)
		copy(body[8:], payload)
		binary.BigEndian.PutUint16(body[2:4], Checksum(body))
	case "udp":
		binary.BigEndian.PutUint16(body[:2], uint16(c.options.LocalPort))
		binary.BigEndian.PutUint16(body[2:4], uint16(c.options.PeerPort))
		binary.BigEndian.PutUint16(body[4:6], uint16(len(body)))
		copy(body[8:], payload)
		checksum := transportChecksum(c.src, c.dst, c.protocol, body)
		if checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(body[6:8], checksum)
	case "tcp":
		binary.BigEndian.PutUint16(body[:2], uint16(c.options.LocalPort))
		binary.BigEndian.PutUint16(body[2:4], uint16(c.options.PeerPort))
		binary.BigEndian.PutUint32(body[4:8], sequence)
		binary.BigEndian.PutUint32(body[8:12], ack)
		body[12], body[13] = 0x50, flags
		binary.BigEndian.PutUint16(body[14:16], 65535)
		if c.options.RawTCP {
			binary.LittleEndian.PutUint16(body[24:26], uint16(len(payload)))
			copy(body[28:], payload)
		} else {
			copy(body[20:], payload)
		}
		binary.BigEndian.PutUint16(body[16:18], transportChecksum(c.src, c.dst, c.protocol, body))
	default:
		copy(body, payload)
	}
	binary.BigEndian.PutUint16(frame[10:12], Checksum(frame[:20]))
	return frame, nil
}

func validIPOptions(options []byte) bool {
	for len(options) != 0 {
		switch options[0] {
		case 0:
			return true
		case 1:
			options = options[1:]
		default:
			if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
				return false
			}
			options = options[int(options[1]):]
		}
	}
	return true
}

func validTCPOptions(options []byte) bool { return validIPOptions(options) }

// Decode validates complete headers, checksums, configured peer admission and
// protocol bounds. The returned payload aliases frame and must be copied before
// the caller reuses its receive buffer. Fragmented frames require Reassembler.
func (c *Codec) Decode(frame []byte) ([]byte, error) {
	if len(frame) < 20 || frame[0]>>4 != 4 {
		return nil, ErrPacket
	}
	header := int(frame[0]&15) * 4
	length := int(binary.BigEndian.Uint16(frame[2:4]))
	maxLength := c.options.MTU
	if c.options.AllowIPFragments {
		maxLength = 65535
	}
	if header < 20 || header > 60 || header > len(frame) || length < header || length > len(frame) || length > maxLength || Checksum(frame[:header]) != 0 || !validIPOptions(frame[20:header]) || binary.BigEndian.Uint16(frame[6:8])&^uint16(0x4000) != 0 {
		return nil, ErrPacket
	}
	if frame[9] != c.protocol || string(frame[12:16]) != string(c.receiveSrc[:]) || string(frame[16:20]) != string(c.receiveDst[:]) {
		return nil, ErrAdmission
	}
	body := frame[header:length]
	switch c.options.Carrier {
	case "icmp":
		if len(body) < 8 || Checksum(body) != 0 {
			return nil, ErrPacket
		}
		typeValue, codeValue := c.options.ICMPType, c.options.ICMPCode
		if c.options.PeerICMPType != nil {
			typeValue = *c.options.PeerICMPType
		}
		if c.options.PeerICMPCode != nil {
			codeValue = *c.options.PeerICMPCode
		}
		if body[0] != typeValue || body[1] != codeValue {
			return nil, ErrAdmission
		}
		if c.options.ICMPIdentifier != nil && binary.BigEndian.Uint16(body[4:6]) != *c.options.ICMPIdentifier {
			return nil, ErrAdmission
		}
		return body[8:], nil
	case "udp":
		if len(body) < 8 || int(binary.BigEndian.Uint16(body[4:6])) != len(body) {
			return nil, ErrPacket
		}
		if int(binary.BigEndian.Uint16(body[:2])) != c.options.PeerPort || int(binary.BigEndian.Uint16(body[2:4])) != c.options.LocalPort {
			return nil, ErrAdmission
		}
		if binary.BigEndian.Uint16(body[6:8]) != 0 && transportChecksum(c.receiveSrc, c.receiveDst, c.protocol, body) != 0 {
			return nil, ErrPacket
		}
		return body[8:], nil
	case "tcp":
		if len(body) < 20 || transportChecksum(c.receiveSrc, c.receiveDst, c.protocol, body) != 0 {
			return nil, ErrPacket
		}
		tcpHeader := int(body[12]>>4) * 4
		if tcpHeader < 20 || tcpHeader > len(body) || body[12]&15 != 0 || !validTCPOptions(body[20:tcpHeader]) {
			return nil, ErrPacket
		}
		peerPort := int(binary.BigEndian.Uint16(body[:2]))
		if peerPort == 0 || !c.options.PeerPortAny && peerPort != c.options.PeerPort || int(binary.BigEndian.Uint16(body[2:4])) != c.options.LocalPort || !c.admitTCPFlags(body[13]) {
			return nil, ErrAdmission
		}
		payload := body[tcpHeader:]
		if c.options.RawTCP {
			if len(payload) < 9 {
				return nil, ErrPacket
			}
			length := int(binary.LittleEndian.Uint16(payload[4:6]))
			if length < 1 || length > len(payload)-8 {
				return nil, ErrPacket
			}
			return payload[8 : 8+length], nil
		}
		return payload, nil
	default:
		return body, nil
	}
}

// DecodePeer returns the admitted logical peer and its actual transport source
// port. It is useful for a RawTCP listener with the explicit port wildcard.
func (c *Codec) DecodePeer(frame []byte) ([]byte, net.Addr, error) {
	payload, err := c.Decode(frame)
	if err != nil {
		return nil, nil, err
	}
	port := c.options.PeerPort
	if c.options.Carrier == "tcp" || c.options.Carrier == "udp" {
		header := int(frame[0]&15) * 4
		port = int(binary.BigEndian.Uint16(frame[header : header+2]))
	}
	return payload, &net.UDPAddr{IP: append(net.IP(nil), c.options.PeerIP.To4()...), Port: port}, nil
}

func EncodeIPv4(options Options, payload []byte, id uint16) ([]byte, error) {
	c, err := NewCodec(options)
	if err != nil {
		return nil, err
	}
	return c.Encode(payload, id)
}

func DecodeIPv4(options Options, frame []byte) ([]byte, error) {
	c, err := NewCodec(options)
	if err != nil {
		return nil, err
	}
	return c.Decode(frame)
}

func ParseTCPFlags(values []string) (uint8, error) {
	var flags uint8
	lookup := map[string]uint8{"FIN": TCPFIN, "SYN": TCPSYN, "RST": TCPRST, "PSH": TCPPSH, "ACK": TCPACK, "URG": TCPURG, "ECE": TCPECE, "CWR": TCPCWR, "F": TCPFIN, "S": TCPSYN, "R": TCPRST, "P": TCPPSH, "A": TCPACK, "U": TCPURG, "E": TCPECE, "C": TCPCWR}
	for _, name := range values {
		value, ok := lookup[strings.ToUpper(name)]
		if !ok {
			for _, letter := range strings.ToUpper(name) {
				value, ok = lookup[string(letter)]
				if !ok {
					return 0, fmt.Errorf("%w: unknown TCP flag", ErrPacket)
				}
				flags |= value
			}
			if name == "" {
				return 0, ErrPacket
			}
			continue
		}
		flags |= value
	}
	return flags, nil
}

func ParseTCPFlagCycle(values []string) ([]uint8, error) {
	cycle := make([]uint8, 0, len(values))
	for _, value := range values {
		flags, err := ParseTCPFlags([]string{value})
		if err != nil {
			return nil, err
		}
		cycle = append(cycle, flags)
	}
	return cycle, nil
}

func EncodeEthernet(local, router net.HardwareAddr, ipv4Packet []byte) ([]byte, error) {
	if len(local) != 6 || len(router) != 6 || len(ipv4Packet) < 20 || ipv4Packet[0]>>4 != 4 {
		return nil, ErrPacket
	}
	frame := make([]byte, 14+len(ipv4Packet))
	copy(frame[:6], router)
	copy(frame[6:12], local)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], ipv4Packet)
	return frame, nil
}

func DecodeEthernet(local net.HardwareAddr, frame []byte) ([]byte, error) {
	if len(local) != 6 || len(frame) < 14 || string(frame[:6]) != string(local) {
		return nil, ErrAdmission
	}
	typeValue := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	for tags := 0; typeValue == 0x8100 || typeValue == 0x88a8; tags++ {
		if tags >= 2 || len(frame) < offset+4 {
			return nil, ErrPacket
		}
		typeValue = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if typeValue != 0x0800 || len(frame) < offset+20 {
		return nil, ErrPacket
	}
	return frame[offset:], nil
}
