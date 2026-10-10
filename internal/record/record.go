// Independent protocol reconstruction by ir_spoof; https://t.me/ir_spoof.
// Package record implements bounded stream records recovered from the reference
// Linux core. Recovery of framing is separate from peer interoperability proof.
package record

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	EncryptedChunkMax = 0xffe0
	PaddedChunkMax    = 0x3fe1
	RecordMax         = 0xffff
	CompressionLimit  = 1 << 20
)

var (
	ErrRecord         = errors.New("record: invalid frame")
	ErrNonce          = errors.New("record: invalid or replayed nonce")
	ErrAuthentication = errors.New("record: authentication failed")
	ErrLimit          = errors.New("record: configured size limit exceeded")
)

// Stealth applies local random padding and bounded optional timing jitter.
// JitterLimitBytes is a caller-supplied policy: zero disables its byte threshold.
type Stealth struct {
	PaddingEnabled   bool
	PaddingMin       int
	PaddingMax       int
	JitterEnabled    bool
	JitterMinMS      int
	JitterMaxMS      int
	JitterLimitBytes int64
}

func (s Stealth) validate() error {
	if s.PaddingMin < 0 || s.PaddingMax > 255 || s.PaddingMin > s.PaddingMax {
		return fmt.Errorf("%w: padding must be within 0..255", ErrRecord)
	}
	if s.JitterMinMS < 0 || s.JitterMaxMS < s.JitterMinMS || s.JitterMaxMS > 60000 || s.JitterLimitBytes < 0 {
		return fmt.Errorf("%w: invalid jitter bounds", ErrRecord)
	}
	return nil
}

func (s Stealth) padding(chunk, maximum int) (int, error) {
	if !s.PaddingEnabled || s.PaddingMax == 0 {
		return 0, nil
	}
	high := min(s.PaddingMax, maximum-chunk)
	low := min(s.PaddingMin, high)
	if high <= 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(high-low+1)))
	if err != nil {
		return 0, err
	}
	return low + int(n.Int64()), nil
}

func (s Stealth) jitter(bytesSent int64, chunk int) error {
	if !s.JitterEnabled || bytesSent == 0 || chunk <= 256 || (s.JitterLimitBytes > 0 && bytesSent >= s.JitterLimitBytes) {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(s.JitterMaxMS-s.JitterMinMS+1)))
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(s.JitterMinMS+int(n.Int64())) * time.Millisecond)
	return nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// A missing body after a complete header is truncation, not a clean stream EOF.
func readBody(r io.Reader, p []byte) error {
	_, err := io.ReadFull(r, p)
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// EncryptedConn uses 2-byte big-endian record length, a 12-byte explicit nonce,
// and AEAD ciphertext of [padding length][random padding][data]. The length
// prefix is associated data. Writes use disjoint even/odd nonce counters.
type EncryptedConn struct {
	net.Conn
	aead                  cipher.AEAD
	stealth               Stealth
	readMu, writeMu       sync.Mutex
	nextSend, nextReceive uint64
	pending               []byte
	readErr, writeErr     error
	bytesSent             int64
}

// NewEncrypted requires a fresh 32-byte key from the authenticated handshake for
// EACH connection. It deliberately performs no static-PSK key derivation.
// sendParity is the negotiated role's 0 or 1; the other peer uses the opposite.
func NewEncrypted(conn net.Conn, sessionKey []byte, algorithm string, sendParity uint8, stealth Stealth) (*EncryptedConn, error) {
	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("%w: session key must be 32 bytes", ErrRecord)
	}
	var aead cipher.AEAD
	var err error
	switch strings.ToLower(algorithm) {
	case "chacha", "chacha20-poly1305":
		aead, err = chacha20poly1305.New(sessionKey)
	case "aes-gcm", "aes-256-gcm":
		var block cipher.Block
		block, err = aes.NewCipher(sessionKey)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported AEAD algorithm", ErrRecord)
	}
	if err != nil {
		return nil, err
	}
	return NewAEAD(conn, aead, sendParity, stealth)
}

func NewAEAD(conn net.Conn, aead cipher.AEAD, sendParity uint8, stealth Stealth) (*EncryptedConn, error) {
	if conn == nil || aead == nil || aead.NonceSize() != 12 || aead.Overhead() != 16 || sendParity > 1 {
		return nil, fmt.Errorf("%w: invalid connection, AEAD or role parity", ErrRecord)
	}
	if err := stealth.validate(); err != nil {
		return nil, err
	}
	return &EncryptedConn{Conn: conn, aead: aead, stealth: stealth, nextSend: uint64(sendParity), nextReceive: uint64(sendParity ^ 1)}, nil
}

func (c *EncryptedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), EncryptedChunkMax)
		if c.nextSend > math.MaxUint64-2 {
			c.writeErr = ErrNonce
			return written, c.writeErr
		}
		pad, err := c.stealth.padding(n, EncryptedChunkMax)
		if err == nil {
			err = c.stealth.jitter(c.bytesSent, n)
		}
		if err != nil {
			c.writeErr = err
			return written, err
		}
		plain := make([]byte, 1+pad+n)
		plain[0] = byte(pad)
		if _, err = io.ReadFull(rand.Reader, plain[1:1+pad]); err != nil {
			c.writeErr = err
			return written, err
		}
		copy(plain[1+pad:], p[:n])
		frame := make([]byte, 2+12, 2+12+len(plain)+16)
		length := 12 + len(plain) + 16
		if length > RecordMax {
			c.writeErr = ErrLimit
			return written, c.writeErr
		}
		binary.BigEndian.PutUint16(frame[:2], uint16(length))
		binary.BigEndian.PutUint64(frame[6:14], c.nextSend)
		c.nextSend += 2
		frame = c.aead.Seal(frame, frame[2:14], plain, frame[:2])
		clear(plain)
		if err = writeFull(c.Conn, frame); err != nil {
			c.writeErr = err
			return written, err
		}
		written += n
		c.bytesSent += int64(n)
		p = p[n:]
	}
	return written, nil
}

func (c *EncryptedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	var header [2]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		c.readErr = err
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length < 30 {
		c.readErr = ErrRecord
		return 0, c.readErr
	}
	body := make([]byte, length)
	if err := readBody(c.Conn, body); err != nil {
		c.readErr = err
		return 0, err
	}
	counter := binary.BigEndian.Uint64(body[4:12])
	// Additional hardening: zero prefix and expected parity. The reference read
	// enforces the forward window and replay bound; its writer emits both invariants.
	if !bytes.Equal(body[:4], []byte{0, 0, 0, 0}) || counter&1 != c.nextReceive&1 || counter < c.nextReceive || counter-c.nextReceive > 0x400 || counter > math.MaxUint64-2 {
		c.readErr = ErrNonce
		return 0, c.readErr
	}
	plain, err := c.aead.Open(nil, body[:12], body[12:], header[:])
	if err != nil {
		c.readErr = ErrAuthentication
		return 0, c.readErr
	}
	if len(plain) == 0 || int(plain[0])+1 >= len(plain) {
		clear(plain)
		c.readErr = ErrRecord
		return 0, c.readErr
	}
	c.nextReceive = counter + 2
	c.pending = plain[1+int(plain[0]):]
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// PaddedConn's 16-bit prefix describes DATA length, excluding its padding byte
// and padding. It is the unencrypted framing, not the encrypted framing.
type PaddedConn struct {
	net.Conn
	stealth           Stealth
	readMu, writeMu   sync.Mutex
	pending           []byte
	readErr, writeErr error
	bytesSent         int64
}

func NewPadded(conn net.Conn, stealth Stealth) (*PaddedConn, error) {
	if conn == nil {
		return nil, ErrRecord
	}
	if err := stealth.validate(); err != nil {
		return nil, err
	}
	return &PaddedConn{Conn: conn, stealth: stealth}, nil
}

func (c *PaddedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), PaddedChunkMax)
		pad, err := c.stealth.padding(n, PaddedChunkMax)
		if err == nil {
			err = c.stealth.jitter(c.bytesSent, n)
		}
		if err != nil {
			c.writeErr = err
			return written, err
		}
		frame := make([]byte, 3+pad+n)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		frame[2] = byte(pad)
		if _, err = io.ReadFull(rand.Reader, frame[3:3+pad]); err != nil {
			c.writeErr = err
			return written, err
		}
		copy(frame[3+pad:], p[:n])
		if err = writeFull(c.Conn, frame); err != nil {
			c.writeErr = err
			return written, err
		}
		written += n
		c.bytesSent += int64(n)
		p = p[n:]
	}
	return written, nil
}

func (c *PaddedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	var header [3]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		c.readErr = err
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(header[:2]))
	if length < 1 || length > PaddedChunkMax {
		c.readErr = ErrRecord
		return 0, c.readErr
	}
	var pad [255]byte
	if err := readBody(c.Conn, pad[:int(header[2])]); err != nil {
		c.readErr = err
		return 0, err
	}
	c.pending = make([]byte, length)
	if err := readBody(c.Conn, c.pending); err != nil {
		c.pending = nil
		c.readErr = err
		return 0, err
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

type CompressionOptions struct {
	Enabled   bool
	Algorithm string
	Level     int
	MinSize   int
	MaxSize   int
}

// CompressedConn uses a four-byte big-endian encoded-data length followed by a
// one-byte compression flag and that data. Advertised "snappy" is the reference
// core's S2 block codec, not a standard Snappy framed stream.
type CompressedConn struct {
	net.Conn
	options           CompressionOptions
	readMu, writeMu   sync.Mutex
	pending           []byte
	readErr, writeErr error
	zenc              *zstd.Encoder
	zdec              *zstd.Decoder
	closeOnce         sync.Once
	closeErr          error
}

func NewCompressed(conn net.Conn, options CompressionOptions) (*CompressedConn, error) {
	if conn == nil {
		return nil, ErrRecord
	}
	if options.MaxSize == 0 {
		options.MaxSize = 65536
	}
	if options.MinSize < 0 || options.MinSize > options.MaxSize || options.MaxSize < 1 || options.MaxSize > CompressionLimit {
		return nil, ErrLimit
	}
	options.Algorithm = strings.ToLower(options.Algorithm)
	if options.Algorithm == "" {
		options.Algorithm = "lz4"
	}
	if options.Algorithm != "lz4" && options.Algorithm != "zstd" && options.Algorithm != "snappy" && options.Algorithm != "s2" && options.Algorithm != "none" {
		return nil, fmt.Errorf("%w: unsupported compression", ErrRecord)
	}
	c := &CompressedConn{Conn: conn, options: options}
	if options.Algorithm == "zstd" {
		level := zstd.SpeedDefault
		if options.Level != 0 {
			level = zstd.EncoderLevelFromZstd(options.Level)
		}
		var err error
		c.zenc, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(level), zstd.WithEncoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		c.zdec, err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(16<<20), zstd.WithDecoderMaxWindow(8<<20), zstd.WithDecodeAllCapLimit(true))
		if err != nil {
			c.zenc.Close()
			return nil, err
		}
	}
	return c, nil
}

func (c *CompressedConn) compress(p []byte) ([]byte, error) {
	switch c.options.Algorithm {
	case "zstd":
		return c.zenc.EncodeAll(p, nil), nil
	case "snappy", "s2":
		return s2.Encode(nil, p), nil
	case "lz4":
		var output bytes.Buffer
		writer := lz4.NewWriter(&output)
		if _, err := writer.Write(p); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return output.Bytes(), nil
	default:
		return p, nil
	}
}

func (c *CompressedConn) decompress(p []byte) ([]byte, error) {
	switch c.options.Algorithm {
	case "zstd":
		return c.zdec.DecodeAll(p, make([]byte, 0, c.options.MaxSize))
	case "snappy", "s2":
		n, err := s2.DecodedLen(p)
		if err != nil {
			return nil, err
		}
		if n < 1 || n > c.options.MaxSize {
			return nil, ErrLimit
		}
		return s2.Decode(make([]byte, 0, n), p)
	case "lz4":
		reader := lz4.NewReader(bytes.NewReader(p))
		decoded, err := io.ReadAll(io.LimitReader(reader, int64(c.options.MaxSize)+1))
		if err != nil {
			return nil, err
		}
		if len(decoded) > c.options.MaxSize {
			return nil, ErrLimit
		}
		return decoded, nil
	default:
		return nil, ErrRecord
	}
}

func (c *CompressedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) > c.options.MaxSize {
		return 0, ErrLimit
	}
	data := p
	flag := byte(0)
	if c.options.Enabled && len(p) >= c.options.MinSize && c.options.Algorithm != "none" {
		compressed, err := c.compress(p)
		if err != nil {
			return 0, err
		}
		if len(compressed) < len(p) {
			data = compressed
			flag = 1
		}
	}
	frame := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	frame[4] = flag
	copy(frame[5:], data)
	if err := writeFull(c.Conn, frame); err != nil {
		c.writeErr = err
		return 0, err
	}
	return len(p), nil
}

func (c *CompressedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	var header [5]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		c.readErr = err
		return 0, err
	}
	length := uint64(binary.BigEndian.Uint32(header[:4]))
	if length < 1 || length > uint64(c.options.MaxSize) {
		c.readErr = ErrLimit
		return 0, c.readErr
	}
	if header[4]&^byte(1) != 0 {
		c.readErr = ErrRecord
		return 0, c.readErr
	}
	data := make([]byte, int(length))
	if err := readBody(c.Conn, data); err != nil {
		c.readErr = err
		return 0, err
	}
	if header[4]&1 != 0 {
		var err error
		data, err = c.decompress(data)
		if err != nil {
			c.readErr = err
			return 0, err
		}
	}
	if len(data) < 1 || len(data) > c.options.MaxSize {
		c.readErr = ErrLimit
		return 0, c.readErr
	}
	c.pending = data
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *CompressedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		c.readMu.Lock()
		defer c.readMu.Unlock()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.readErr = net.ErrClosed
		c.writeErr = net.ErrClosed
		clear(c.pending)
		c.pending = nil
		if c.zenc != nil {
			_ = c.zenc.Close()
		}
		if c.zdec != nil {
			c.zdec.Close()
		}
	})
	return c.closeErr
}
