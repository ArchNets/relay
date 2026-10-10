// Independent Linux reconstruction by t.me/ir_spoof.
// These framing rules were recovered from the v3.0.1 executable.
package wire

import (
	"bufio"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func WriteAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if n < 0 || n > len(p) {
			return errors.New("invalid write result")
		}
		p = p[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func WriteUDP(w io.Writer, addr string, p []byte) error {
	if len(addr) < 1 || len(addr) > 256 || len(p) > 65535 {
		return errors.New("UDP frame exceeds bounds")
	}
	var header [4]byte
	binary.BigEndian.PutUint16(header[:2], uint16(len(addr)))
	binary.BigEndian.PutUint16(header[2:], uint16(len(p)))
	if e := WriteAll(w, header[:]); e != nil {
		return e
	}
	if e := WriteAll(w, []byte(addr)); e != nil {
		return e
	}
	return WriteAll(w, p)
}
func ReadUDP(r io.Reader) (string, []byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return "", nil, e
	}
	a, n := int(binary.BigEndian.Uint16(h[:2])), int(binary.BigEndian.Uint16(h[2:]))
	if a < 1 || a > 256 {
		return "", nil, errors.New("invalid UDP address length")
	}
	data := make([]byte, a+n)
	if _, e := io.ReadFull(r, data); e != nil {
		return "", nil, e
	}
	addr := string(data[:a])
	if strings.ContainsAny(addr, "\r\n\x00") {
		return "", nil, errors.New("invalid UDP address")
	}
	return addr, data[a:], nil
}
func WritePacket(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > 65535 {
		return errors.New("invalid TUN packet length")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if e := WriteAll(w, h[:]); e != nil {
		return e
	}
	return WriteAll(w, p)
}
func ReadPacket(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > 65535 {
		return nil, errors.New("invalid TUN packet length")
	}
	p := make([]byte, int(n))
	_, e := io.ReadFull(r, p)
	return p, e
}

// Line leaves any buffered bytes available for the following SMUX session.
func Line(r *bufio.Reader, max int) (string, error) {
	var b []byte
	for {
		fragment, e := r.ReadSlice('\n')
		if len(b)+len(fragment) > max {
			return "", errors.New("control line exceeds bound")
		}
		b = append(b, fragment...)
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil {
			return "", e
		}
		return strings.TrimSpace(string(b)), nil
	}
}
func NormalizeSecret(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

type Hello struct {
	Role string
	Mux  int
}

func WriteHello(w io.Writer, psk, role string, mux int) error {
	role = strings.ToUpper(role)
	if role != "TUN" && role != "PORTS" {
		return errors.New("invalid tunnel role")
	}
	if mux < 1 || mux > 64 {
		return errors.New("invalid mux count")
	}
	if psk == "" {
		return WriteAll(w, []byte(fmt.Sprintf("ROLE %s MUX=%d\n", role, mux)))
	}
	return WriteAll(w, []byte(fmt.Sprintf("AUTH %s ROLE=%s MUX=%d\n", NormalizeSecret(psk), role, mux)))
}
func ReadHello(r *bufio.Reader, psk string) (Hello, error) {
	h := Hello{Role: "ports", Mux: 1}
	var fields []string
	if psk != "" {
		line, e := Line(r, 4096)
		if e != nil {
			return h, e
		}
		if !strings.HasPrefix(line, "AUTH ") {
			return h, errors.New("authentication failed")
		}
		fields = strings.Fields(strings.TrimPrefix(line, "AUTH "))
		if len(fields) == 0 || subtle.ConstantTimeCompare([]byte(NormalizeSecret(fields[0])), []byte(NormalizeSecret(psk))) != 1 {
			return h, errors.New("authentication failed")
		}
		fields = fields[1:]
	} else {
		prefix, e := r.Peek(4)
		if e != nil {
			return h, e
		}
		if string(prefix) != "ROLE" && string(prefix) != "MUX " {
			return h, nil
		}
		line, e := Line(r, 4096)
		if e != nil {
			return h, e
		}
		fields = strings.Fields(line)
	}
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		upper := strings.ToUpper(f)
		switch {
		case upper == "ROLE":
			if i+1 < len(fields) {
				i++
				h.Role = strings.ToLower(fields[i])
			}
		case strings.HasPrefix(upper, "ROLE=") || strings.HasPrefix(upper, "ROLE:"):
			h.Role = strings.ToLower(f[5:])
		case upper == "TUN" || upper == "PORTS":
			h.Role = strings.ToLower(f)
		case strings.HasPrefix(upper, "MUX=") || strings.HasPrefix(upper, "MUX:"):
			n, e := strconv.Atoi(f[4:])
			if e != nil || n < 1 || n > 64 {
				return h, errors.New("invalid mux count")
			}
			h.Mux = n
		}
	}
	if h.Role != "ports" && h.Role != "tun" {
		return h, errors.New("invalid tunnel role")
	}
	return h, nil
}
