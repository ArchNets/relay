// Record safety and independent known-vector checks by ir_spoof; t.me/ir_spoof.
package record

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type memoryConn struct {
	input                 *bytes.Reader
	output                bytes.Buffer
	readLimit, writeLimit int
	writeZero             bool
}

func (c *memoryConn) Read(p []byte) (int, error) {
	if c.input == nil {
		return 0, io.EOF
	}
	if c.readLimit > 0 && len(p) > c.readLimit {
		p = p[:c.readLimit]
	}
	return c.input.Read(p)
}
func (c *memoryConn) Write(p []byte) (int, error) {
	if c.writeZero {
		return 0, nil
	}
	if c.writeLimit > 0 && len(p) > c.writeLimit {
		p = p[:c.writeLimit]
	}
	return c.output.Write(p)
}
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

func encrypted(t *testing.T, c net.Conn, algorithm string, parity uint8, stealth Stealth) *EncryptedConn {
	t.Helper()
	// A zero key is a public test-vector input, never a production session key.
	wrapped, err := NewEncrypted(c, make([]byte, 32), algorithm, parity, stealth)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

func TestEncryptedIndependentKnownVectors(t *testing.T) {
	// Expected bytes were independently produced using Python cryptography's
	// AESGCM/ChaCha20Poly1305 implementations, key=0, nonce=0, AAD=0x0020.
	vectors := map[string]string{
		"aes-gcm": "0020000000000000000000000000cec6225e3a7c57f6f90996bc9279ddf07ff89e08",
		"chacha":  "00200000000000000000000000009f6685ddee37577d34090c86157c2e8fb9a6ddfe",
	}
	for algorithm, expected := range vectors {
		t.Run(algorithm, func(t *testing.T) {
			wire := &memoryConn{writeLimit: 2}
			writer := encrypted(t, wire, algorithm, 0, Stealth{})
			if n, err := writer.Write([]byte("abc")); err != nil || n != 3 {
				t.Fatalf("write: %d %v", n, err)
			}
			if got := hex.EncodeToString(wire.output.Bytes()); got != expected {
				t.Fatalf("wire %s", got)
			}
			reader := encrypted(t, &memoryConn{input: bytes.NewReader(wire.output.Bytes()), readLimit: 1}, algorithm, 1, Stealth{})
			plain, err := io.ReadAll(reader)
			if err != nil || string(plain) != "abc" {
				t.Fatalf("read %q %v", plain, err)
			}
		})
	}
}

func TestEncryptedReplayTamperParityAndForwardWindow(t *testing.T) {
	for _, kind := range []string{"replay", "tag", "length-aad", "parity", "prefix", "window"} {
		t.Run(kind, func(t *testing.T) {
			wire := &memoryConn{}
			writer := encrypted(t, wire, "aes-gcm", 0, Stealth{})
			if kind == "window" {
				writer.nextSend = 0x402
			}
			if _, err := writer.Write([]byte("abc")); err != nil {
				t.Fatal(err)
			}
			frame := append([]byte(nil), wire.output.Bytes()...)
			parity := uint8(1)
			switch kind {
			case "replay":
				frame = append(frame, frame...)
			case "tag":
				frame[len(frame)-1] ^= 1
			case "length-aad":
				frame[1]++
				frame = append(frame, 0)
			case "parity":
				parity = 0
			case "prefix":
				frame[2] = 1
			}
			reader := encrypted(t, &memoryConn{input: bytes.NewReader(frame)}, "aes-gcm", parity, Stealth{})
			data, err := io.ReadAll(reader)
			if err == nil {
				t.Fatal("bad record accepted")
			}
			if kind == "replay" && string(data) != "abc" {
				t.Fatalf("first authenticated record lost: %q", data)
			}
			if kind != "replay" && len(data) != 0 {
				t.Fatal("unauthenticated plaintext was released")
			}
			if _, again := reader.Read(make([]byte, 1)); again == nil {
				t.Fatal("failed read did not remain failed")
			}
		})
	}
}

func TestEncryptedTruncatedRecordsNeverReleasePlaintext(t *testing.T) {
	wire := &memoryConn{}
	if _, err := encrypted(t, wire, "chacha", 0, Stealth{}).Write([]byte("test payload")); err != nil {
		t.Fatal(err)
	}
	frame := wire.output.Bytes()
	for cut := 1; cut < len(frame); cut++ {
		reader := encrypted(t, &memoryConn{input: bytes.NewReader(frame[:cut]), readLimit: 1}, "chacha", 1, Stealth{})
		data, err := io.ReadAll(reader)
		if err == nil || len(data) != 0 {
			t.Fatalf("truncation %d accepted", cut)
		}
	}
}

func TestEncryptedChunkPaddingAndNonceBounds(t *testing.T) {
	input := bytes.Repeat([]byte("x"), EncryptedChunkMax+32)
	wire := &memoryConn{}
	writer := encrypted(t, wire, "aes-gcm", 0, Stealth{PaddingEnabled: true, PaddingMin: 255, PaddingMax: 255})
	if n, err := writer.Write(input); err != nil || n != len(input) {
		t.Fatalf("write %d %v", n, err)
	}
	frame := wire.output.Bytes()
	first := int(binary.BigEndian.Uint16(frame[:2]))
	if first != EncryptedChunkMax+29 {
		t.Fatalf("first-frame cap %d", first)
	}
	if second := binary.BigEndian.Uint64(frame[first+2+6 : first+2+14]); second != 2 {
		t.Fatalf("second nonce %d", second)
	}
	reader := encrypted(t, &memoryConn{input: bytes.NewReader(frame), readLimit: 7}, "aes-gcm", 1, Stealth{})
	decoded, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(decoded, input) {
		t.Fatalf("round trip failed %v", err)
	}
	writer.nextSend = ^uint64(0)
	if _, err := writer.Write([]byte("x")); !errors.Is(err, ErrNonce) {
		t.Fatalf("nonce overflow accepted %v", err)
	}
}

func TestEncryptedInvalidAuthenticatedPadding(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	plain := []byte{255, 1}
	header := []byte{0, byte(12 + 16 + len(plain))}
	nonce := make([]byte, 12)
	frame := append(append([]byte(nil), header...), nonce...)
	frame = aead.Seal(frame, nonce, plain, header)
	reader := encrypted(t, &memoryConn{input: bytes.NewReader(frame)}, "aes-gcm", 1, Stealth{})
	if _, err := reader.Read(make([]byte, 8)); !errors.Is(err, ErrRecord) {
		t.Fatalf("bad padding accepted %v", err)
	}
}

func TestPaddedKnownFrameAndChunkLimits(t *testing.T) {
	wire := &memoryConn{writeLimit: 1}
	writer, err := NewPadded(wire, Stealth{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire.output.Bytes()); got != "000300616263" {
		t.Fatal(got)
	}
	reader, _ := NewPadded(&memoryConn{input: bytes.NewReader(wire.output.Bytes()), readLimit: 1}, Stealth{})
	plain, err := io.ReadAll(reader)
	if err != nil || string(plain) != "abc" {
		t.Fatalf("decode %q %v", plain, err)
	}
	wire = &memoryConn{}
	writer, _ = NewPadded(wire, Stealth{PaddingEnabled: true, PaddingMin: 255, PaddingMax: 255})
	input := bytes.Repeat([]byte("y"), PaddedChunkMax+10)
	if _, err = writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if wire.output.Bytes()[2] != 0 {
		t.Fatal("max chunk added padding despite zero room")
	}
	reader, _ = NewPadded(&memoryConn{input: bytes.NewReader(wire.output.Bytes()), readLimit: 3}, Stealth{})
	plain, err = io.ReadAll(reader)
	if err != nil || !bytes.Equal(plain, input) {
		t.Fatal("padded chunks failed")
	}
}

func TestPaddedTruncationAndHostileLength(t *testing.T) {
	for _, frame := range [][]byte{{0}, {0, 3}, {0, 3, 0}, {0, 3, 2, 1}, {0, 3, 0, 'a'}, {0, 0, 0}, {0xff, 0xff, 0}} {
		reader, _ := NewPadded(&memoryConn{input: bytes.NewReader(frame)}, Stealth{})
		if data, err := io.ReadAll(reader); err == nil || len(data) != 0 {
			t.Fatalf("accepted %x", frame)
		}
		if data, err := reader.Read(make([]byte, 16)); err == nil || data != 0 {
			t.Fatal("truncation did not remain terminal")
		}
	}
}

func compressed(t *testing.T, conn net.Conn, algorithm string, maxSize int) *CompressedConn {
	t.Helper()
	wrapped, err := NewCompressed(conn, CompressionOptions{Enabled: true, Algorithm: algorithm, MinSize: 64, MaxSize: maxSize})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	return wrapped
}

func TestCompressionFormatAndRoundTrip(t *testing.T) {
	for _, algorithm := range []string{"lz4", "zstd", "snappy"} {
		t.Run(algorithm, func(t *testing.T) {
			wire := &memoryConn{writeLimit: 5}
			writer := compressed(t, wire, algorithm, 65536)
			input := bytes.Repeat([]byte("ir_spoof test payload "), 700)
			if n, err := writer.Write(input); err != nil || n != len(input) {
				t.Fatalf("write %d %v", n, err)
			}
			frame := wire.output.Bytes()
			if frame[4] != 1 || int(binary.BigEndian.Uint32(frame[:4])) != len(frame)-5 {
				t.Fatalf("bad envelope %x", frame[:5])
			}
			if algorithm == "lz4" && !bytes.Equal(frame[5:9], []byte{4, 0x22, 0x4d, 0x18}) {
				t.Fatal("not an LZ4 framed stream")
			}
			if algorithm == "zstd" && !bytes.Equal(frame[5:9], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
				t.Fatal("not a Zstd frame")
			}
			reader := compressed(t, &memoryConn{input: bytes.NewReader(frame), readLimit: 2}, algorithm, 65536)
			decoded, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(decoded, input) {
				t.Fatalf("round trip %d %v", len(decoded), err)
			}
		})
	}
}

func TestCompressionLiteralAndS2KnownBlock(t *testing.T) {
	wire := &memoryConn{}
	writer := compressed(t, wire, "snappy", 64)
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire.output.Bytes()); got != "0000000300616263" {
		t.Fatal(got)
	}
	// S2/Snappy literal block: decoded size 3, literal tag 0x08, then abc.
	frame, _ := hex.DecodeString("00000005010308616263")
	reader := compressed(t, &memoryConn{input: bytes.NewReader(frame), readLimit: 1}, "snappy", 64)
	decoded, err := io.ReadAll(reader)
	if err != nil || string(decoded) != "abc" {
		t.Fatalf("known block %q %v", decoded, err)
	}
}

func TestCompressionExpansionBound(t *testing.T) {
	for _, algorithm := range []string{"lz4", "zstd", "snappy"} {
		t.Run(algorithm, func(t *testing.T) {
			wire := &memoryConn{}
			writer := compressed(t, wire, algorithm, 65536)
			if _, err := writer.Write(bytes.Repeat([]byte("q"), 8192)); err != nil {
				t.Fatal(err)
			}
			reader := compressed(t, &memoryConn{input: bytes.NewReader(wire.output.Bytes())}, algorithm, 512)
			if decoded, err := io.ReadAll(reader); err == nil || len(decoded) != 0 {
				t.Fatal("expansion escaped bound")
			}
		})
	}
	for _, frame := range [][]byte{{0xff, 0xff, 0xff, 0xff, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 1, 2, 'x'}, {0, 0, 0, 5, 0}, {0, 0, 0, 5, 0, 'x'}} {
		reader := compressed(t, &memoryConn{input: bytes.NewReader(frame)}, "snappy", 64)
		if _, err := io.ReadAll(reader); err == nil {
			t.Fatalf("hostile frame %x", frame)
		}
	}
}

func TestEncryptedOppositeRolesAndForwardWindowBoundary(t *testing.T) {
	for _, parity := range []uint8{0, 1} {
		wire := &memoryConn{}
		writer := encrypted(t, wire, "chacha", parity, Stealth{})
		writer.nextSend += 0x400
		if _, err := writer.Write([]byte("edge")); err != nil {
			t.Fatal(err)
		}
		reader := encrypted(t, &memoryConn{input: bytes.NewReader(wire.output.Bytes())}, "chacha", parity^1, Stealth{})
		if data, err := io.ReadAll(reader); err != nil || string(data) != "edge" {
			t.Fatalf("role %d maximum window: %q %v", parity, data, err)
		}
	}
}

func TestCompressedCloseClearsBufferedPlaintextAndRejectsFurtherIO(t *testing.T) {
	wire := &memoryConn{}
	writer := compressed(t, wire, "zstd", 4096)
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 1000)); err != nil {
		t.Fatal(err)
	}
	reader := compressed(t, &memoryConn{input: bytes.NewReader(wire.output.Bytes())}, "zstd", 4096)
	if n, err := reader.Read(make([]byte, 1)); err != nil || n != 1 {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if len(reader.pending) != 0 {
		t.Fatal("closed reader retained plaintext")
	}
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close %d %v", n, err)
	}
	if n, err := reader.Write([]byte("x")); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close %d %v", n, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteFailureIsStickyAndNoProgressDoesNotLoop(t *testing.T) {
	for _, kind := range []string{"encrypted", "padded", "compressed"} {
		t.Run(kind, func(t *testing.T) {
			wire := &memoryConn{writeZero: true}
			var writer io.Writer
			switch kind {
			case "encrypted":
				writer = encrypted(t, wire, "chacha", 0, Stealth{})
			case "padded":
				writer, _ = NewPadded(wire, Stealth{})
			case "compressed":
				writer = compressed(t, wire, "lz4", 64)
			}
			if _, err := writer.Write([]byte("abc")); !errors.Is(err, io.ErrNoProgress) {
				t.Fatal(err)
			}
			wire.writeZero = false
			if _, err := writer.Write([]byte("abc")); !errors.Is(err, io.ErrNoProgress) {
				t.Fatal("write error not sticky")
			}
			if wire.output.Len() != 0 {
				t.Fatal("failed stream continued writing")
			}
		})
	}
}

func TestConcurrentEncryptedWritesDoNotInterleaveRecords(t *testing.T) {
	wire := &memoryConn{writeLimit: 3}
	writer := encrypted(t, wire, "chacha", 0, Stealth{PaddingEnabled: true, PaddingMax: 32})
	var workers sync.WaitGroup
	for i := 0; i < 24; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := writer.Write(bytes.Repeat([]byte("z"), 128)); err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	reader := encrypted(t, &memoryConn{input: bytes.NewReader(wire.output.Bytes()), readLimit: 3}, "chacha", 1, Stealth{})
	decoded, err := io.ReadAll(reader)
	if err != nil || len(decoded) != 24*128 {
		t.Fatalf("concurrent frames: %d %v", len(decoded), err)
	}
}
