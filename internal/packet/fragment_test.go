// Fragment fixtures and hostile-input bounds by ir_spoof; https://t.me/ir_spoof.
package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func fragmentFixture(t *testing.T, carrier string) (*Codec, [][]byte, []byte) {
	t.Helper()
	value := options(carrier)
	value.AllowIPFragments = true
	value.MTU = 100
	codec, err := NewCodec(opposite(value))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("bounded fragment data"), 16)
	frame, err := EncodeIPv4(value, payload, 42)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(frame[6:8]) != 0 {
		t.Fatal("DF was not cleared")
	}
	parts, err := FragmentIPv4(frame, value.MTU)
	if err != nil || len(parts) < 3 {
		t.Fatalf("fragments %d %v", len(parts), err)
	}
	return codec, parts, payload
}

func TestIPv4FragmentsReorderDuplicateAndCompleteTransport(t *testing.T) {
	for _, carrier := range []string{"raw", "icmp"} {
		t.Run(carrier, func(t *testing.T) {
			codec, parts, payload := fragmentFixture(t, carrier)
			r := NewReassembler(codec)
			now := time.Unix(1, 0)
			if _, err := r.Assemble(parts[1], now); !errors.Is(err, ErrFragmentPending) {
				t.Fatal(err)
			}
			if _, err := r.Assemble(parts[1], now); !errors.Is(err, ErrFragmentPending) {
				t.Fatal("duplicate", err)
			}
			for i := len(parts) - 1; i >= 0; i-- {
				if i == 1 {
					continue
				}
				complete, err := r.Assemble(parts[i], now)
				if i > 0 {
					if !errors.Is(err, ErrFragmentPending) {
						t.Fatal(err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := codec.Decode(complete)
				if err != nil || !bytes.Equal(data, payload) {
					t.Fatal("reassembly failed", err)
				}
			}
			if r.bytes != 0 || len(r.sets) != 0 {
				t.Fatal("completed fragments retained")
			}
		})
	}
}

func TestIPv4FragmentsRejectConflictAndExpire(t *testing.T) {
	codec, parts, _ := fragmentFixture(t, "raw")
	now := time.Unix(1, 0)
	for _, mutate := range []func([]byte){
		func(p []byte) { p[20] ^= 1 },
		func(p []byte) { binary.BigEndian.PutUint16(p[6:8], 0x2001); repairIP(p) },
		func(p []byte) { binary.BigEndian.PutUint16(p[6:8], 0x6000); repairIP(p) },
	} {
		r := NewReassembler(codec)
		_, _ = r.Assemble(parts[0], now)
		bad := append([]byte(nil), parts[0]...)
		mutate(bad)
		if _, err := r.Assemble(bad, now); err == nil || errors.Is(err, ErrFragmentPending) {
			t.Fatal("malformed or conflicting fragment accepted")
		}
	}
	r := NewReassembler(codec)
	_, _ = r.Assemble(parts[0], now)
	if _, err := r.Assemble(parts[1], now.Add(fragmentLifetime)); !errors.Is(err, ErrFragmentPending) {
		t.Fatal(err)
	}
	if r.bytes != len(parts[1])-20 {
		t.Fatal("expired first fragment retained")
	}
	wrong := append([]byte(nil), parts[0]...)
	wrong[15] ^= 1
	repairIP(wrong)
	before := r.bytes
	if _, err := r.Assemble(wrong, now); !errors.Is(err, ErrAdmission) || r.bytes != before {
		t.Fatal("foreign peer allocated fragment state")
	}
	for _, part := range parts {
		for n := 0; n < len(part); n++ {
			if _, err := NewReassembler(codec).Assemble(part[:n], now); err == nil {
				t.Fatalf("truncation %d accepted", n)
			}
		}
	}
}

func TestIPv4FragmentAllocationLimitsAndTransmissionBounds(t *testing.T) {
	codec, parts, _ := fragmentFixture(t, "raw")
	r := NewReassembler(codec)
	now := time.Unix(1, 0)
	for id := 0; id < maxFragmentFlows+1; id++ {
		part := append([]byte(nil), parts[0]...)
		binary.BigEndian.PutUint16(part[4:6], uint16(id))
		repairIP(part)
		_, err := r.Assemble(part, now)
		if id < maxFragmentFlows && !errors.Is(err, ErrFragmentPending) {
			t.Fatal(err)
		}
		if id == maxFragmentFlows && !errors.Is(err, ErrPacket) {
			t.Fatal("flow limit bypassed")
		}
	}
	if len(r.sets) != maxFragmentFlows || r.bytes > maxFragmentBytes {
		t.Fatal("reassembly bound")
	}
	value := options("raw")
	frame, _ := EncodeIPv4(value, bytes.Repeat([]byte{1}, 100), 1)
	if _, err := FragmentIPv4(frame, 68); !errors.Is(err, ErrMTU) {
		t.Fatal("DF fragmented")
	}
	value.AllowIPFragments = true
	frame, _ = EncodeIPv4(value, bytes.Repeat([]byte{1}, 65515), 1)
	if _, err := FragmentIPv4(frame, 68); !errors.Is(err, ErrMTU) {
		t.Fatal("too many TX fragments accepted")
	}
	value.Carrier = "udp"
	if _, err := NewCodec(value); err == nil {
		t.Fatal("UDP silently ignored fragmentation")
	}
}

func TestRecoveredRawConstructorDefaults(t *testing.T) {
	value := options("tcp")
	value.RawTCP = true
	value.LocalFlags = 0
	client, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := client.Encode([]byte("a"), 0)
	if err != nil || binary.BigEndian.Uint32(frame[24:28]) != 1 || binary.BigEndian.Uint32(frame[28:32]) != 1 || frame[33] != TCPACK {
		t.Fatal("client constructor defaults", err)
	}
	if client.tcpFlags(2) != TCPPSH|TCPACK {
		t.Fatal("client PA/A cycle")
	}
	value.PeerPort = 0
	value.PeerPortAny = true
	server, err := NewCodec(value)
	if err != nil || server.tcpFlags(1) != TCPPSH|TCPACK || server.tcpFlags(2) != TCPPSH|TCPACK {
		t.Fatal("listener PA default", err)
	}
}

func FuzzIPv4FragmentReassembler(f *testing.F) {
	value := options("raw")
	value.AllowIPFragments = true
	codec, _ := NewCodec(opposite(value))
	frame, _ := EncodeIPv4(value, bytes.Repeat([]byte{1}, 200), 1)
	parts, _ := FragmentIPv4(frame, 100)
	for _, part := range parts {
		f.Add(part)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReassembler(codec)
		now := time.Unix(1, 0)
		for i := 0; i < 3; i++ {
			_, _ = r.Assemble(data, now.Add(time.Duration(i)*time.Second))
		}
		if r.bytes < 0 || r.bytes > maxFragmentBytes || len(r.sets) > maxFragmentFlows {
			t.Fatal("fragment allocation bound")
		}
	})
}
