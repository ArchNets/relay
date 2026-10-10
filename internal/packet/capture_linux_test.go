// Owned capture filter tests by ir_spoof; https://t.me/ir_spoof.
//go:build linux

package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func filterVM(t *testing.T, filter []unix.SockFilter) *bpf.VM {
	t.Helper()
	var raw []bpf.RawInstruction
	for _, instruction := range filter {
		raw = append(raw, bpf.RawInstruction{Op: instruction.Code, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K})
	}
	instructions, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("invalid BPF")
	}
	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatal(err)
	}
	return vm
}

func TestLinuxCustomFilterCannotBypassOwnedPeerAdmission(t *testing.T) {
	value := options("raw")
	codec, _ := NewCodec(value)
	c := &socketConn{codec: codec}
	custom := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 20},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: 'x'},
		{Code: unix.BPF_RET | unix.BPF_K, K: 65535},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	combined, err := combineCaptureFilters(custom, c.socketFilter())
	if err != nil {
		t.Fatal(err)
	}
	vm := filterVM(t, combined)
	frame, _ := EncodeIPv4(opposite(value), []byte("x allowed"), 1)
	if n, err := vm.Run(frame); err != nil || n == 0 {
		t.Fatal("valid filtered packet rejected", err)
	}
	for _, offset := range []int{12, 16, 20} {
		bad := append([]byte(nil), frame...)
		bad[offset] ^= 1
		if n, err := vm.Run(bad); err != nil || n != 0 {
			t.Fatal("custom filter bypass", err)
		}
	}
	custom[3].Code = unix.BPF_RET | unix.BPF_A
	if _, err := combineCaptureFilters(custom, c.socketFilter()); err == nil {
		t.Fatal("dynamic result accepted")
	}
	custom = []unix.SockFilter{{Code: unix.BPF_JMP | unix.BPF_JA, K: 1}, {Code: unix.BPF_RET | unix.BPF_K, K: 0}}
	if _, err := combineCaptureFilters(custom, c.socketFilter()); err == nil {
		t.Fatal("out-of-program jump admitted")
	}
}

func TestLinuxRawWildcardCyclesAndFragmentCapture(t *testing.T) {
	value := options("tcp")
	value.RawTCP = true
	value.PeerPortAny = true
	value.PeerPort = 0
	value.RemoteFlagCycle = []uint8{TCPPSH | TCPACK, TCPACK}
	codec, _ := NewCodec(value)
	vm := filterVM(t, (&socketConn{codec: codec}).socketFilter())
	client := opposite(options("tcp"))
	client.RawTCP = true
	client.LocalPort = 34000
	for _, flags := range []uint8{TCPPSH | TCPACK, TCPACK, TCPRST} {
		client.LocalFlagCycle = []uint8{flags}
		frame, _ := EncodeIPv4(client, []byte("x"), 1)
		n, err := vm.Run(frame)
		if err != nil || (n > 0) != (flags != TCPRST) {
			t.Fatal("raw flags/wildcard", err)
		}
	}
	value = options("icmp")
	value.AllowIPFragments = true
	value.MTU = 100
	codec, _ = NewCodec(value)
	vm = filterVM(t, (&socketConn{codec: codec}).socketFilter())
	frame, _ := EncodeIPv4(opposite(value), make([]byte, 200), 2)
	parts, _ := FragmentIPv4(frame, 100)
	for _, part := range parts {
		if n, err := vm.Run(part); err != nil || n == 0 {
			t.Fatal("fragment dropped", err)
		}
	}
	parts[1][12] ^= 1
	if n, err := vm.Run(parts[1]); err != nil || n != 0 {
		t.Fatal("foreign fragment admitted", err)
	}
	value.PcapPromisc = true
	value.AFPacket = true
	value.PcapSnaplen = 100
	codec, _ = NewCodec(value)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	foreign, _ := net.ParseMAC("02:00:00:00:00:99")
	c := &socketConn{codec: codec, ethernet: true, localMAC: mac}
	vm = filterVM(t, c.socketFilter())
	frame, _ = EncodeIPv4(opposite(value), []byte("x"), 3)
	frame, _ = EncodeEthernet(mac, foreign, frame)
	if n, err := vm.Run(frame); err != nil || n == 0 || n > 100 {
		t.Fatal("scoped promiscuous capture", err)
	}
	frame[14+16] ^= 1
	binary.BigEndian.PutUint16(frame[14+10:14+12], 0)
	if n, err := vm.Run(frame); err != nil || n != 0 {
		t.Fatal("promiscuous foreign peer admitted", err)
	}
}

func TestLinuxOptionalOfflineTCPDumpCompilation(t *testing.T) {
	if _, err := compileLibpcapFilter("ip", 1500); errors.Is(err, errLibpcapUnavailable) {
		if _, err := trustedHelper("tcpdump"); err != nil {
			t.Skip("trusted local libpcap/tcpdump not installed")
		}
	} else if err != nil {
		t.Fatal(err)
	}
	filter, err := compileCaptureFilter("ip and host 10.0.0.2", 1500)
	if err != nil {
		t.Fatal(err)
	}
	if len(filter) == 0 {
		t.Fatal("empty compiled filter")
	}
	if _, err := compileCaptureFilter("invalid (((", 1500); err == nil {
		t.Fatal("invalid filter compiled")
	}
}
