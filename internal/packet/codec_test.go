// Carrier fixtures and hostile-input checks by ir_spoof; https://t.me/ir_spoof.
package packet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"
)

func options(carrier string) Options {
	return Options{Carrier: carrier, LocalIP: net.ParseIP("10.0.0.1"), PeerIP: net.ParseIP("10.0.0.2"), LocalPort: 1234, PeerPort: 5678, LocalFlags: TCPSYN | TCPACK, RemoteFlags: TCPSYN | TCPACK, ICMPType: 8, MTU: 1500}
}

func opposite(value Options) Options {
	value.LocalIP, value.PeerIP = value.PeerIP, value.LocalIP
	value.LocalPort, value.PeerPort = value.PeerPort, value.LocalPort
	value.LocalFlags, value.RemoteFlags = value.RemoteFlags, value.LocalFlags
	return value
}

func TestInternetChecksumKnownHeaderAndOddLength(t *testing.T) {
	header, _ := hex.DecodeString("45000073000040004011b861c0a80001c0a800c7")
	if Checksum(header) != 0 {
		t.Fatal("known IPv4 checksum failed")
	}
	header[10], header[11] = 0, 0
	if Checksum(header) != 0xb861 {
		t.Fatal("wrong IPv4 checksum")
	}
	if Checksum([]byte{0, 1, 255}) != 0xfe || Checksum(nil) != 0xffff {
		t.Fatal("odd checksum bounds")
	}
	if Checksum(bytes.Repeat([]byte{255}, 200000)) != 0 {
		t.Fatal("long checksum overflow")
	}
}

func TestCarrierIndependentKnownFixtures(t *testing.T) {
	// Expected full packets were independently serialized/checksummed with
	// Python's struct module; they are standard-header fixtures, not reference
	// application captures or proof of reference-core interoperability.
	vectors := map[string]string{
		"raw":  "45000017002a400040fd25be0a0000010a000002616263",
		"icmp": "4500001f002a4000400126b20a0000010a00000208002ea104d2002a616263",
		"udp":  "4500001f002a4000401126a20a0000010a00000204d2162e000b0c73616263",
		"tcp":  "4500002b002a4000400626a10a0000010a00000204d2162e0000002a000000005012ffffbc400000616263",
	}
	for carrier, expected := range vectors {
		t.Run(carrier, func(t *testing.T) {
			frame, err := EncodeIPv4(options(carrier), []byte("abc"), 42)
			if err != nil || hex.EncodeToString(frame) != expected {
				t.Fatalf("fixture %x %v", frame, err)
			}
			payload, err := DecodeIPv4(opposite(options(carrier)), frame)
			if err != nil || string(payload) != "abc" {
				t.Fatalf("decode %q %v", payload, err)
			}
		})
	}
}

func TestRecoveredRawTCPEnvelopeAndSequenceFlags(t *testing.T) {
	value := options("tcp")
	value.RawTCP = true
	value.TCPSequence = 1000
	value.TCPAck = 2000
	value.LocalFlagCycle = []uint8{TCPSYN | TCPACK, TCPPSH | TCPACK}
	codec, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	if codec.PayloadMTU() != 1452 {
		t.Fatal("raw prefix missing from MTU")
	}
	frame, err := codec.Encode([]byte("abc"), 1)
	const expected = "4500003300010000400666c20a0000010a00000204d2162e000003e8000007d05012ffffadaa00000000000003000000616263"
	if err != nil || hex.EncodeToString(frame) != expected {
		t.Fatalf("recovered fixture %x %v", frame, err)
	}
	peer := opposite(value)
	peer.RemoteFlagCycle = value.LocalFlagCycle
	decoder, err := NewCodec(peer)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := decoder.Decode(frame); err != nil || string(data) != "abc" {
		t.Fatalf("raw decode %q %v", data, err)
	}
	second, err := codec.EncodeTCP([]byte("abc"), 2, 1011, 2000, codec.tcpFlags(1011))
	if err != nil || second[33] != TCPPSH|TCPACK {
		t.Fatal("sequence-selected flag cycle failed")
	}
	if data, err := decoder.Decode(second); err != nil || string(data) != "abc" {
		t.Fatal("flag cycle admission failed")
	}
	for _, length := range []uint16{0, 4, 65535} {
		bad := append([]byte(nil), frame...)
		binary.LittleEndian.PutUint16(bad[44:46], length)
		repairTransport(bad, 16)
		if _, err := decoder.Decode(bad); err == nil {
			t.Fatal("invalid raw length accepted")
		}
	}
	bad := append([]byte(nil), frame...)
	bad[33] = TCPRST
	repairTransport(bad, 16)
	if _, err := decoder.Decode(bad); !errors.Is(err, ErrAdmission) {
		t.Fatal("unconfigured raw flag admitted")
	}
	// The reference read only bounds the LE data length; it ignores the other
	// prefix bytes. Preserve that behavior rather than inventing a new magic.
	frame[40], frame[46] = 99, 88
	repairTransport(frame, 16)
	if data, err := decoder.Decode(frame); err != nil || string(data) != "abc" {
		t.Fatal("opaque reserved prefix rejected")
	}
	if _, err := codec.Encode(nil, 0); err == nil {
		t.Fatal("zero-size raw envelope emitted")
	}
	cycle, err := ParseTCPFlagCycle([]string{"SA", "PA", "R"})
	if err != nil || !bytes.Equal(cycle, []byte{TCPSYN | TCPACK, TCPPSH | TCPACK, TCPRST}) {
		t.Fatal("reference-style short flag cycle failed")
	}
}

func TestRecoveredRawListenerAdmitsPeerPortsAndReturnsValidatedAddress(t *testing.T) {
	server := options("tcp")
	server.RawTCP = true
	server.PeerPort = 0
	server.PeerPortAny = true
	decoder, err := NewCodec(server)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{34001, 34002} {
		client := opposite(options("tcp"))
		client.RawTCP = true
		client.LocalPort = port
		frame, err := EncodeIPv4(client, []byte("kcp"), 1)
		if err != nil {
			t.Fatal(err)
		}
		payload, addr, err := decoder.DecodePeer(frame)
		if err != nil || string(payload) != "kcp" || addr.(*net.UDPAddr).Port != port || !addr.(*net.UDPAddr).IP.Equal(server.PeerIP) {
			t.Fatalf("dynamic port %q %v %v", payload, addr, err)
		}
		addr.(*net.UDPAddr).IP[3] = 99
		if !decoder.options.PeerIP.Equal(server.PeerIP) {
			t.Fatal("returned address mutated admission")
		}
		frame[20], frame[21] = 0, 0
		repairTransport(frame, 16)
		if _, err := decoder.Decode(frame); err == nil {
			t.Fatal("zero source port admitted")
		}
	}
	if _, err := decoder.Encode([]byte("reply-without-peer"), 0); !errors.Is(err, ErrAdmission) {
		t.Fatal("listener emitted to unspecified port")
	}
	server.RawTCP = false
	if _, err := NewCodec(server); err == nil {
		t.Fatal("generic carrier allowed dynamic peer ports")
	}
}

func TestPayloadMTUAndTruncation(t *testing.T) {
	for _, carrier := range []string{"raw", "pcap", "icmp", "udp", "tcp"} {
		t.Run(carrier, func(t *testing.T) {
			codec, err := NewCodec(options(carrier))
			if err != nil {
				t.Fatal(err)
			}
			frame, err := codec.Encode(make([]byte, codec.PayloadMTU()), 0)
			if err != nil || len(frame) != 1500 {
				t.Fatalf("MTU %d %v", len(frame), err)
			}
			if _, err = codec.Encode(make([]byte, codec.PayloadMTU()+1), 0); !errors.Is(err, ErrMTU) {
				t.Fatal("oversized payload accepted")
			}
			decoder, _ := NewCodec(opposite(options(carrier)))
			for cut := 0; cut < len(frame); cut++ {
				if _, err = decoder.Decode(frame[:cut]); err == nil {
					t.Fatalf("accepted truncation %d", cut)
				}
			}
			withLinkPadding := append(append([]byte(nil), frame...), 0, 0, 0)
			if data, err := decoder.Decode(withLinkPadding); err != nil || len(data) != codec.PayloadMTU() {
				t.Fatal("valid link padding rejected")
			}
		})
	}
}

func repairIP(frame []byte) {
	header := int(frame[0]&15) * 4
	frame[10], frame[11] = 0, 0
	binary.BigEndian.PutUint16(frame[10:12], Checksum(frame[:header]))
}

func repairTransport(frame []byte, offset int) {
	body := frame[int(frame[0]&15)*4 : int(binary.BigEndian.Uint16(frame[2:4]))]
	body[offset], body[offset+1] = 0, 0
	var source, destination [4]byte
	copy(source[:], frame[12:16])
	copy(destination[:], frame[16:20])
	binary.BigEndian.PutUint16(body[offset:offset+2], transportChecksum(source, destination, frame[9], body))
}

func TestSpoofAddressesAndExplicitReceiveAdmission(t *testing.T) {
	value := options("udp")
	value.SpoofSrcIP = net.ParseIP("203.0.113.8")
	value.SpoofDstIP = net.ParseIP("203.0.113.9")
	frame, err := EncodeIPv4(value, []byte("opaque"), 1)
	if err != nil {
		t.Fatal(err)
	}
	peer := opposite(options("udp"))
	if _, err = DecodeIPv4(peer, frame); !errors.Is(err, ErrAdmission) {
		t.Fatal("unexpected wire address accepted")
	}
	peer.ReceiveSrcIP = value.SpoofSrcIP
	peer.ReceiveDstIP = value.SpoofDstIP
	if data, err := DecodeIPv4(peer, frame); err != nil || string(data) != "opaque" {
		t.Fatalf("spoof fixture %q %v", data, err)
	}
	frame[15] ^= 1
	repairIP(frame)
	if _, err = DecodeIPv4(peer, frame); !errors.Is(err, ErrAdmission) {
		t.Fatal("unconfigured source accepted")
	}
}

func TestMalformedIPAndTransport(t *testing.T) {
	for _, carrier := range []string{"raw", "icmp", "udp", "tcp"} {
		frame, _ := EncodeIPv4(options(carrier), []byte("bounded payload"), 5)
		decoder, _ := NewCodec(opposite(options(carrier)))
		mutations := map[string]func([]byte){
			"version":                func(p []byte) { p[0] = 0x65 },
			"small-ihl":              func(p []byte) { p[0] = 0x44 },
			"huge-ihl":               func(p []byte) { p[0] = 0x4f },
			"total-too-short":        func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 19); repairIP(p) },
			"total-too-long":         func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 65535); repairIP(p) },
			"ip-checksum":            func(p []byte) { p[10] ^= 1 },
			"fragment":               func(p []byte) { p[6] = 0x20; repairIP(p) },
			"fragment-offset":        func(p []byte) { p[7] = 1; repairIP(p) },
			"reserved-fragment-flag": func(p []byte) { p[6] = 0x80; repairIP(p) },
			"wrong-protocol":         func(p []byte) { p[9]++; repairIP(p) },
			"wrong-peer":             func(p []byte) { p[15]++; repairIP(p) },
			"wrong-destination":      func(p []byte) { p[19]++; repairIP(p) },
		}
		if carrier != "raw" {
			mutations["transport-checksum"] = func(p []byte) { p[len(p)-1] ^= 1 }
		}
		if carrier == "udp" {
			mutations["udp-length"] = func(p []byte) { p[25]++; repairTransport(p, 6) }
			mutations["udp-port"] = func(p []byte) { p[21]++; repairTransport(p, 6) }
		}
		if carrier == "tcp" {
			mutations["tcp-port"] = func(p []byte) { p[21]++; repairTransport(p, 16) }
			mutations["tcp-offset"] = func(p []byte) { p[32] = 0x40; repairTransport(p, 16) }
			mutations["tcp-flags"] = func(p []byte) { p[33] = TCPRST; repairTransport(p, 16) }
		}
		if carrier == "icmp" {
			mutations["icmp-type"] = func(p []byte) { p[20] = 0; p[22], p[23] = 0, 0; binary.BigEndian.PutUint16(p[22:24], Checksum(p[20:])) }
		}
		for name, mutate := range mutations {
			t.Run(carrier+"/"+name, func(t *testing.T) {
				bad := append([]byte(nil), frame...)
				mutate(bad)
				if _, err := decoder.Decode(bad); err == nil {
					t.Fatal("malformed/admission packet accepted")
				}
			})
		}
	}
}

func TestVariableIPv4AndTCPOptions(t *testing.T) {
	frame, _ := EncodeIPv4(options("tcp"), []byte("body"), 3)
	// Four-byte NOP/NOP/EOL/pad options inserted into the TCP header.
	frame = append(append(append([]byte(nil), frame[:40]...), 1, 1, 0, 0), frame[40:]...)
	frame[32] = 0x60
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	repairTransport(frame, 16)
	repairIP(frame)
	// Four-byte NOP/NOP/EOL/pad options inserted into the IPv4 header.
	frame = append(append(append([]byte(nil), frame[:20]...), 1, 1, 0, 0), frame[20:]...)
	frame[0] = 0x46
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	repairIP(frame)
	decoder, _ := NewCodec(opposite(options("tcp")))
	if data, err := decoder.Decode(frame); err != nil || string(data) != "body" {
		t.Fatalf("variable headers %q %v", data, err)
	}
	frame[20], frame[21] = 7, 1
	repairIP(frame)
	if _, err := decoder.Decode(frame); err == nil {
		t.Fatal("invalid IPv4 option length accepted")
	}
}

func TestEthernetAdmissionAndVLANBounds(t *testing.T) {
	local, _ := net.ParseMAC("02:00:00:00:00:01")
	peer, _ := net.ParseMAC("02:00:00:00:00:02")
	ip, _ := EncodeIPv4(options("raw"), []byte("body"), 1)
	frame, err := EncodeEthernet(local, peer, ip)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := DecodeEthernet(peer, frame); err != nil || !bytes.Equal(data, ip) {
		t.Fatal("Ethernet decode failed")
	}
	if _, err := DecodeEthernet(local, frame); !errors.Is(err, ErrAdmission) {
		t.Fatal("wrong receiver MAC accepted")
	}
	for tags := 1; tags <= 3; tags++ {
		frame = append(append(append([]byte(nil), frame[:12]...), 0x81, 0, 0, 1), frame[12:]...)
		data, err := DecodeEthernet(peer, frame)
		if tags <= 2 && (err != nil || !bytes.Equal(data, ip)) {
			t.Fatal("bounded VLAN tags rejected")
		}
		if tags == 3 && err == nil {
			t.Fatal("unbounded VLAN stack accepted")
		}
	}
	if _, err := EncodeEthernet(local[:5], peer, ip); err == nil {
		t.Fatal("short MAC accepted")
	}
}

func TestOptionsValidationAndImmutableAdmission(t *testing.T) {
	for _, mutate := range []func(*Options){
		func(o *Options) { o.LocalIP = nil }, func(o *Options) { o.PeerIP = net.ParseIP("::1") }, func(o *Options) { o.PeerIP = net.IPv4bcast }, func(o *Options) { o.LocalIP = net.IPv4zero }, func(o *Options) { o.PeerIP = net.ParseIP("224.0.0.1") }, func(o *Options) { o.MTU = 67 }, func(o *Options) { o.MTU = 65536 }, func(o *Options) { o.LocalPort = -1 }, func(o *Options) { o.PeerPort = 65536 }, func(o *Options) { o.Carrier = "unknown" }, func(o *Options) { o.Carrier = "tcp"; o.Protocol = 17 }, func(o *Options) { o.Carrier = "udp"; o.LocalPort = 0 }, func(o *Options) { o.Interface = "bad\x00interface" },
	} {
		value := options("raw")
		mutate(&value)
		if _, err := NewCodec(value); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	value := options("raw")
	codec, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	value.LocalIP.To4()[3] = 42
	value.PeerIP.To4()[3] = 43
	frame, err := codec.Encode([]byte("x"), 0)
	if err != nil || frame[15] != 1 || frame[19] != 2 {
		t.Fatal("caller mutated live wire addresses")
	}
	flags, err := ParseTCPFlags([]string{"syn", "ACK", "SYN"})
	if err != nil || flags != TCPSYN|TCPACK {
		t.Fatal("flag mapping failed")
	}
	if _, err := ParseTCPFlags([]string{"arbitrary"}); err == nil {
		t.Fatal("invalid flags accepted")
	}
}

func FuzzDecodeIPv4(f *testing.F) {
	for _, carrier := range []string{"raw", "icmp", "udp", "tcp"} {
		frame, _ := EncodeIPv4(options(carrier), []byte("seed"), 0)
		f.Add(frame)
	}
	f.Add([]byte{0x45})
	value := options("tcp")
	value.RawTCP = true
	frame, _ := EncodeIPv4(value, []byte("raw-seed"), 0)
	f.Add(frame)
	decoders := make([]*Codec, 0, 4)
	for _, carrier := range []string{"raw", "icmp", "udp", "tcp"} {
		c, _ := NewCodec(opposite(options(carrier)))
		decoders = append(decoders, c)
	}
	decoder, _ := NewCodec(opposite(value))
	decoders = append(decoders, decoder)
	f.Fuzz(func(t *testing.T, frame []byte) {
		for _, decoder := range decoders {
			payload, err := decoder.Decode(frame)
			if err == nil && len(payload) > decoder.PayloadMTU() {
				t.Fatal("payload escaped bound")
			}
		}
	})
}
