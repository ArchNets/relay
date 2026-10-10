// Recovered ICMP identifier admission by ir_spoof; https://t.me/ir_spoof.
package packet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func TestRecoveredICMPIdentifierAndOwnedOverride(t *testing.T) {
	identifier := uint16(509)
	value := options("icmp")
	value.ICMPIdentifier = &identifier
	codec, err := NewCodec(value)
	if err != nil {
		t.Fatal(err)
	}
	// The recovered L3 SID fold selects 509, independently of carrier ports.
	// This independently checksummed standard-header vector checks byte order.
	identifier = 40001
	frame, err := codec.Encode([]byte("abc"), 42)
	const expected = "4500001f002a4000400126b20a0000010a0000020800317601fd002a616263"
	if err != nil || hex.EncodeToString(frame) != expected {
		t.Fatalf("identifier vector %x %v", frame, err)
	}
	peerIdentifier := uint16(509)
	peer := opposite(value)
	peer.ICMPIdentifier = &peerIdentifier
	decoder, err := NewCodec(peer)
	if err != nil {
		t.Fatal(err)
	}
	peerIdentifier = 1
	if data, err := decoder.Decode(frame); err != nil || string(data) != "abc" {
		t.Fatalf("identifier admission %q %v", data, err)
	}
	for _, wrong := range []uint16{0, 508, 40001} {
		bad := append([]byte(nil), frame...)
		binary.BigEndian.PutUint16(bad[24:26], wrong)
		binary.BigEndian.PutUint16(bad[22:24], 0)
		binary.BigEndian.PutUint16(bad[22:24], Checksum(bad[20:]))
		if _, err := decoder.Decode(bad); !errors.Is(err, ErrAdmission) {
			t.Fatalf("wrong identifier %d admitted: %v", wrong, err)
		}
	}
}

func TestICMPGenericIdentifierFallbackAndExplicitZero(t *testing.T) {
	value := options("icmp")
	frame, err := EncodeIPv4(value, []byte("payload"), 1)
	if err != nil || binary.BigEndian.Uint16(frame[24:26]) != uint16(value.LocalPort) {
		t.Fatal("generic local-port identifier changed", err)
	}
	// A nil override preserves the generic receive behavior across unequal ports.
	if _, err := DecodeIPv4(opposite(value), frame); err != nil {
		t.Fatal(err)
	}
	zero := uint16(0)
	value.ICMPIdentifier = &zero
	frame, err = EncodeIPv4(value, []byte("payload"), 2)
	if err != nil || binary.BigEndian.Uint16(frame[24:26]) != 0 {
		t.Fatal("explicit zero identifier ignored", err)
	}
	if _, err := DecodeIPv4(opposite(value), frame); err != nil {
		t.Fatal(err)
	}
}
