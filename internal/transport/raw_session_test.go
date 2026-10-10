// Actual KCP constructor wire regression by t.me/ir_spoof.
package transport

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

type capturedRawSocket struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
}

func (s *capturedRawSocket) ReadFrom([]byte) (int, net.Addr, error) {
	<-s.closed
	return 0, nil, net.ErrClosed
}
func (s *capturedRawSocket) WriteTo(packet []byte, _ net.Addr) (int, error) {
	select {
	case s.packets <- append([]byte(nil), packet...):
		return len(packet), nil
	case <-s.closed:
		return 0, net.ErrClosed
	}
}
func (s *capturedRawSocket) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
func (s *capturedRawSocket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 40002}
}
func (s *capturedRawSocket) SetDeadline(time.Time) error      { return nil }
func (s *capturedRawSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *capturedRawSocket) SetWriteDeadline(time.Time) error { return nil }

func TestRawConstructorEmitsZeroConversationAndOwnsSocket(t *testing.T) {
	socket := &capturedRawSocket{packets: make(chan []byte, 16), closed: make(chan struct{})}
	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4000}
	session, err := newRawSession(peer, 10, 3, socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close(); socket.Close() })
	session.SetNoDelay(1, 10, 2, 1)
	if _, err := session.Write([]byte("initial raw peer handshake")); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-socket.packets:
		// The ordinary KCP FEC data header is eight bytes. Its first KCP word
		// is the conversation; the next byte is the PUSH command.
		if len(packet) < 8+24 || binary.LittleEndian.Uint16(packet[4:6]) != 0xf1 || binary.LittleEndian.Uint32(packet[8:12]) != 0 || packet[12] != 81 {
			t.Fatalf("reference raw KCP conversation/framing mismatch: %x", packet)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("raw KCP constructor did not emit a packet")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-socket.closed:
	case <-time.After(time.Second):
		t.Fatal("raw session did not close its owned packet socket")
	}
}
