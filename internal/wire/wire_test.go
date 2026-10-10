// Independent reconstruction tests by t.me/ir_spoof.
package wire

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

type tinyWriter struct{ bytes.Buffer }

func (w *tinyWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}
func TestObservedUDPVector(t *testing.T) {
	var b tinyWriter
	if e := WriteUDP(&b, "a:1", []byte{0, 255}); e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(b.Bytes()) != "00030002613a3100ff" {
		t.Fatalf("wrong bytes %x", b.Bytes())
	}
	a, p, e := ReadUDP(&b)
	if e != nil || a != "a:1" || !bytes.Equal(p, []byte{0, 255}) {
		t.Fatal(a, p, e)
	}
}
func TestObservedTUNVector(t *testing.T) {
	var b bytes.Buffer
	WritePacket(&b, []byte{0x45, 0})
	if hex.EncodeToString(b.Bytes()) != "000000024500" {
		t.Fatal("wrong TUN frame")
	}
	p, e := ReadPacket(&b)
	if e != nil || len(p) != 2 {
		t.Fatal(e)
	}
}
func TestMalformedLengths(t *testing.T) {
	for _, p := range [][]byte{{0, 0, 0, 1}, {1, 1, 0, 0}, {0, 3, 0, 2, 1}} {
		if _, _, e := ReadUDP(bytes.NewReader(p)); e == nil {
			t.Fatal("accepted bad UDP")
		}
	}
	for _, p := range [][]byte{{0, 1, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 2, 1}} {
		if _, e := ReadPacket(bytes.NewReader(p)); e == nil {
			t.Fatal("accepted bad TUN")
		}
	}
}
func TestHelloKeepsSMUXReadAhead(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("AUTH test ROLE=TUN MUX=4\n\x02\x00smux"))
	h, e := ReadHello(r, "test")
	if e != nil || h.Role != "tun" || h.Mux != 4 {
		t.Fatal(h, e)
	}
	b, e := io.ReadAll(r)
	if e != nil || string(b) != "\x02\x00smux" {
		t.Fatal(b, e)
	}
}
func TestHelloAuthAndBounds(t *testing.T) {
	for _, s := range []string{"AUTH other ROLE=PORTS MUX=1\n", "AUTH test ROLE=PORTS MUX=9999999\n", "AUTH test ROLE=website MUX=1\n"} {
		if _, e := ReadHello(bufio.NewReader(bytes.NewBufferString(s)), "test"); e == nil {
			t.Fatal("accepted invalid peer hello")
		}
	}
}
