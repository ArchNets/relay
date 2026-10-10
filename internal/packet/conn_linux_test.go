//go:build linux

// Linux syscall lifecycle tests by ir_spoof; https://t.me/ir_spoof.
// These tests use local AF_UNIX socket pairs, not host IP interfaces.
package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func TestLinuxFragmentedDatagramSocketReadWrite(t *testing.T) {
	c, peer := localSocketFixture(t)
	value := options("raw")
	value.MTU, value.AllowIPFragments = 100, true
	codec, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	c.codec, c.fragments = codec, NewReassembler(codec)
	payload := bytes.Repeat([]byte("data"), 50)
	if n, err := c.WriteTo(payload, c.peer); err != nil || n != len(payload) {
		t.Fatal("fragmented write", n, err)
	}
	readerCodec, _ := NewCodec(opposite(value))
	reassembler := NewReassembler(readerCodec)
	var complete []byte
	for i := 0; i < 3; i++ {
		buffer := make([]byte, 200)
		n, _, err := unix.Recvfrom(peer, buffer, 0)
		if err != nil {
			t.Fatal(err)
		}
		complete, err = reassembler.Assemble(buffer[:n], time.Now())
		if i < 2 && !errors.Is(err, ErrFragmentPending) || i == 2 && err != nil {
			t.Fatal("fragmented syscall", err)
		}
	}
	if data, err := readerCodec.Decode(complete); err != nil || !bytes.Equal(data, payload) {
		t.Fatal("fragmented TX payload", err)
	}
	frame, _ := EncodeIPv4(opposite(value), payload, 1)
	frames, _ := FragmentIPv4(frame, 100)
	for i := len(frames) - 1; i >= 0; i-- {
		if err := unix.Sendto(peer, frames[i], 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 300)
	n, _, err := c.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatal("fragmented RX payload", err)
	}
}

func localSocketFixture(t *testing.T) (*socketConn, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewCodec(options("raw"))
	if err != nil {
		t.Fatal(err)
	}
	c := &socketConn{codec: codec, fd: fds[0], readWake: -1, writeWake: -1, local: address(codec.options.LocalIP, codec.options.LocalPort), peer: address(codec.options.PeerIP, codec.options.PeerPort)}
	c.readWake, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	c.writeWake, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = unix.Close(fds[1]) })
	return c, fds[1]
}

func TestLinuxReadDeadlineUpdateAndReset(t *testing.T) {
	c, peer := localSocketFixture(t)
	result := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 100)); result <- err }()
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("deadline: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadline did not wake blocked read")
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	bad, _ := EncodeIPv4(options("raw"), []byte("wrong direction"), 0)
	good, _ := EncodeIPv4(opposite(options("raw")), []byte("valid"), 0)
	if err := unix.Sendto(peer, bad, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(peer, good, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 100)
	n, addr, err := c.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "valid" || !peerAddress(addr, c.peer) {
		t.Fatalf("reset read %q %v %v", buffer[:n], addr, err)
	}
}

func TestLinuxCloseWakesReadAndWrite(t *testing.T) {
	c, _ := localSocketFixture(t)
	// Fill the local Unix datagram queue so WriteTo must wait for writability.
	for {
		err := unix.Sendto(c.fd, []byte("fill"), unix.MSG_DONTWAIT, nil)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	reads, writes := make(chan error, 1), make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 10)); reads <- err }()
	go func() { _, err := c.WriteTo([]byte("payload"), c.peer); writes <- err }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	for _, result := range []chan error{reads, writes} {
		select {
		case err := <-result:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close did not terminate: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("close left an operation blocked")
		}
	}
	if err := c.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("deadline accepted on closed socket")
	}
	if err := c.Close(); err != nil {
		t.Fatal("repeat close", err)
	}
}

func TestLinuxRecoveredRawSequenceAdvancesByEnvelopeLength(t *testing.T) {
	c, peer := localSocketFixture(t)
	value := options("tcp")
	value.RawTCP = true
	value.LocalFlagCycle = []uint8{TCPSYN | TCPACK, TCPPSH | TCPACK}
	codec, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	c.codec, c.sequence, c.ack = codec, 1000, 2000
	var previousID uint16
	for index, expectedSequence := range []uint32{1000, 1011} {
		if n, err := c.WriteTo([]byte("abc"), c.peer); err != nil || n != 3 {
			t.Fatalf("raw write %d %v", n, err)
		}
		buffer := make([]byte, 200)
		n, _, err := unix.Recvfrom(peer, buffer, 0)
		if err != nil {
			t.Fatal(err)
		}
		frame := buffer[:n]
		if binary.BigEndian.Uint32(frame[24:28]) != expectedSequence || binary.BigEndian.Uint32(frame[28:32]) != 2000 {
			t.Fatal("raw TCP state mismatch")
		}
		if frame[33] != value.LocalFlagCycle[index] {
			t.Fatal("raw flag sequence mismatch")
		}
		id := binary.BigEndian.Uint16(frame[4:6])
		if index > 0 && id != previousID+1 {
			t.Fatal("raw IPv4 ID not monotonic")
		}
		previousID = id
	}
}

func TestLinuxRecoveredRawListenerRepliesOnlyToConfiguredPeerIP(t *testing.T) {
	c, peer := localSocketFixture(t)
	value := options("tcp")
	value.RawTCP = true
	value.PeerPort = 0
	value.PeerPortAny = true
	codec, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	c.codec = codec
	c.peer = address(value.PeerIP, 0)
	for index, port := range []int{34001, 34002, 34001, 34002} {
		remote := address(value.PeerIP, port)
		if n, err := c.WriteTo([]byte("reply"), remote); err != nil || n != 5 {
			t.Fatalf("dynamic write %d %v", n, err)
		}
		buffer := make([]byte, 200)
		n, _, err := unix.Recvfrom(peer, buffer, 0)
		if err != nil {
			t.Fatal(err)
		}
		if n < 40 || int(binary.BigEndian.Uint16(buffer[22:24])) != port {
			t.Fatal("reply encoded wrong dynamic destination port")
		}
		sequence := uint32(1)
		if index >= 2 {
			sequence += 13
		}
		if binary.BigEndian.Uint32(buffer[24:28]) != sequence || binary.BigEndian.Uint32(buffer[28:32]) != 1 {
			t.Fatal("listener state was shared between different peer ports")
		}
	}
	for _, addr := range []net.Addr{address(net.ParseIP("10.0.0.99"), 34001), address(value.PeerIP, 0), (*net.UDPAddr)(nil)} {
		if _, err := c.WriteTo([]byte("reply"), addr); !errors.Is(err, ErrAdmission) {
			t.Fatal("unconfigured peer accepted")
		}
	}
}

func TestLinuxOwnedFilterWithIndependentBPFInterpreter(t *testing.T) {
	for _, carrier := range []string{"raw", "icmp", "udp", "tcp"} {
		for _, ethernet := range []bool{false, true} {
			value := options(carrier)
			codec, err := NewCodec(value)
			if err != nil {
				t.Fatal(err)
			}
			mac, _ := net.ParseMAC("02:00:00:00:00:01")
			peerMAC, _ := net.ParseMAC("02:00:00:00:00:02")
			c := &socketConn{codec: codec, ethernet: ethernet, localMAC: mac}
			var raw []bpf.RawInstruction
			for _, instruction := range c.socketFilter() {
				raw = append(raw, bpf.RawInstruction{Op: instruction.Code, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K})
			}
			instructions, allDecoded := bpf.Disassemble(raw)
			if !allDecoded {
				t.Fatal("invalid BPF")
			}
			vm, err := bpf.NewVM(instructions)
			if err != nil {
				t.Fatal(err)
			}
			frame, _ := EncodeIPv4(opposite(value), []byte("opaque"), 4)
			if ethernet {
				frame, err = EncodeEthernet(peerMAC, mac, frame)
				if err != nil {
					t.Fatal(err)
				}
			}
			if n, err := vm.Run(frame); err != nil || n == 0 {
				t.Fatalf("valid %s Ethernet=%t dropped %d %v", carrier, ethernet, n, err)
			}
			base := 0
			if ethernet {
				base = 14
			}
			for _, offset := range []int{base + 9, base + 15, base + 19} {
				bad := append([]byte(nil), frame...)
				bad[offset] ^= 1
				if n, err := vm.Run(bad); err != nil || n != 0 {
					t.Fatalf("filter admitted wrong peer/protocol %d %v", n, err)
				}
			}
			if carrier == "udp" || carrier == "tcp" {
				bad := append([]byte(nil), frame...)
				bad[base+21] ^= 1
				if n, err := vm.Run(bad); err != nil || n != 0 {
					t.Fatal("filter admitted wrong port")
				}
			}
			if ethernet {
				bad := append([]byte(nil), frame...)
				bad[5] ^= 1
				if n, err := vm.Run(bad); err != nil || n != 0 {
					t.Fatal("filter admitted wrong receiver MAC")
				}
			}
		}
	}
}
