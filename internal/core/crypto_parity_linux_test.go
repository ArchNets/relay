//go:build linux

// Independent Linux reconstruction by t.me/ir_spoof.
package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"netrix.local/ir_spoof/internal/config"
)

// Capture the actual Engine.crypto constructor path without a socket peer or
// the record package's decoder. An independent AES-GCM decoder verifies that
// both emitted records use the recovered physical-role nonce and length AAD.
func TestLegacyCryptoUsesPhysicalConnectionParity(t *testing.T) {
	for _, mode := range []string{"client", "server"} {
		for _, direct := range []bool{false, true} {
			for _, dial := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/direct=%t/dial=%t", mode, direct, dial), func(t *testing.T) {
					key := make([]byte, 32) // Public test vector, never a deployment secret.
					cfg := &config.Config{Mode: mode, Direct: direct,
						Encryption: &config.Encryption{Enabled: true, Algorithm: "aes-256-gcm", Key: hex.EncodeToString(key)},
						Stealth:    &config.Stealth{}}
					capture := &parityCaptureConn{}
					engine := &Engine{Config: cfg, Legacy: true}
					conn, err := engine.crypto(capture, dial)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					payloads := [][]byte{[]byte("first wire record"), []byte("second wire record")}
					for _, payload := range payloads {
						if n, err := conn.Write(payload); err != nil || n != len(payload) {
							t.Fatalf("write = %d, %v", n, err)
						}
					}
					block, err := aes.NewCipher(key)
					if err != nil {
						t.Fatal(err)
					}
					aead, err := cipher.NewGCM(block)
					if err != nil {
						t.Fatal(err)
					}
					wire := capture.Bytes()
					first := uint64(1)
					if dial {
						first = 0
					}
					for i, payload := range payloads {
						if len(wire) < 2 {
							t.Fatal("truncated record length")
						}
						length := int(binary.BigEndian.Uint16(wire[:2]))
						if length < 29 || len(wire) < 2+length {
							t.Fatalf("invalid captured record length %d", length)
						}
						frame := wire[:2+length]
						wire = wire[2+length:]
						nonce := frame[2:14]
						if !bytes.Equal(nonce[:4], make([]byte, 4)) || binary.BigEndian.Uint64(nonce[4:]) != first+uint64(2*i) {
							t.Fatalf("record %d nonce = %x, want zero prefix and counter %d", i, nonce, first+uint64(2*i))
						}
						plain, err := aead.Open(nil, nonce, frame[14:], frame[:2])
						if err != nil {
							t.Fatalf("independent decrypt record %d: %v", i, err)
						}
						if !bytes.Equal(plain, append([]byte{0}, payload...)) {
							t.Fatalf("record %d plaintext = %x", i, plain)
						}
					}
					if len(wire) != 0 {
						t.Fatalf("unexpected trailing wire bytes: %d", len(wire))
					}
				})
			}
		}
	}
}

type parityCaptureConn struct{ bytes.Buffer }

func (*parityCaptureConn) Close() error                     { return nil }
func (*parityCaptureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*parityCaptureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*parityCaptureConn) SetDeadline(time.Time) error      { return nil }
func (*parityCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (*parityCaptureConn) SetWriteDeadline(time.Time) error { return nil }
