//go:build linux

// Independent Linux reconstruction by t.me/ir_spoof.
package core

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/xtaci/smux"
	"io"
	"net"
	"netrix.local/ir_spoof/internal/config"
	"netrix.local/ir_spoof/internal/record"
	"netrix.local/ir_spoof/internal/wire"
	"strings"
	"sync"
	"time"
)

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *bufferedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}

type pool struct {
	mu      sync.Mutex
	items   []*smux.Session
	changed chan struct{}
}

func newPool() *pool { return &pool{changed: make(chan struct{})} }

// Backends can accept streams without ever calling open. Prune on every pool
// access and clear the old slice tail so reconnects cannot retain closed peers.
// The caller holds p.mu.
func (p *pool) pruneLocked() {
	alive := p.items[:0]
	for _, s := range p.items {
		if s != nil && !s.IsClosed() {
			alive = append(alive, s)
		}
	}
	clear(p.items[len(alive):])
	p.items = alive
}

func (p *pool) add(s *smux.Session) {
	p.mu.Lock()
	p.pruneLocked()
	p.items = append(p.items, s)
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}
func (p *pool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	return len(p.items)
}
func (p *pool) open(ctx context.Context) (*smux.Stream, error) {
	for {
		p.mu.Lock()
		p.pruneLocked()
		var best *smux.Session
		for _, s := range p.items {
			if best == nil || s.NumStreams() < best.NumStreams() {
				best = s
			}
		}
		changed := p.changed
		p.mu.Unlock()
		if best != nil {
			s, e := best.OpenStream()
			if e == nil {
				return s, nil
			}
			if !best.IsClosed() {
				return nil, e
			}
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (p *pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.items {
		s.Close()
	}
	p.items = nil
	close(p.changed)
	p.changed = make(chan struct{})
}
func smuxConfig(c *config.Config) *smux.Config {
	s := smux.DefaultConfig()
	s.Version = c.SMUX.Version
	s.KeepAliveInterval = time.Duration(c.SMUX.Keepalive) * time.Second
	s.KeepAliveTimeout = 3 * s.KeepAliveInterval
	s.MaxFrameSize = c.SMUX.FrameSize
	s.MaxReceiveBuffer = c.SMUX.MaxRecv
	s.MaxStreamBuffer = c.SMUX.MaxStream
	return s
}
func baseKey(c *config.Config) ([]byte, error) {
	key := wire.NormalizeSecret(c.Encryption.Key)
	if key == "" {
		key = wire.NormalizeSecret(c.PSK)
	}
	if key == "" {
		return nil, errors.New("encryption needs a local key or peer secret")
	}
	candidate := strings.TrimPrefix(strings.TrimPrefix(key, "0x"), "0X")
	if b, e := hex.DecodeString(candidate); e == nil && len(b) == 32 {
		return b, nil
	}
	hash := sha256.Sum256([]byte(key))
	return hash[:], nil
}

// Fresh nonces from BOTH peers prevent the reference's repeated-key/counter issue.
// The NRX4 exchange is only used by the independent encrypted wire mode.
func freshKey(conn net.Conn, key []byte, dial bool) ([]byte, error) {
	var client, server [32]byte
	var h [36]byte
	copy(h[:4], "NRX4")
	if dial {
		if _, e := rand.Read(client[:]); e != nil {
			return nil, e
		}
		copy(h[4:], client[:])
		if e := wire.WriteAll(conn, h[:]); e != nil {
			return nil, e
		}
		if _, e := io.ReadFull(conn, h[:]); e != nil {
			return nil, e
		}
		if string(h[:4]) != "NRX4" {
			return nil, errors.New("peer needs independent encrypted wire mode")
		}
		copy(server[:], h[4:])
	} else {
		if _, e := io.ReadFull(conn, h[:]); e != nil {
			return nil, e
		}
		if string(h[:4]) != "NRX4" {
			return nil, errors.New("peer needs independent encrypted wire mode")
		}
		copy(client[:], h[4:])
		if _, e := rand.Read(server[:]); e != nil {
			return nil, e
		}
		copy(h[:4], "NRX4")
		copy(h[4:], server[:])
		if e := wire.WriteAll(conn, h[:]); e != nil {
			return nil, e
		}
	}
	salt := append(client[:], server[:]...)
	extract := hmac.New(sha256.New, salt)
	extract.Write(key)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("netrix ir_spoof session v4\x01"))
	return expand.Sum(nil), nil
}
func (e *Engine) crypto(conn net.Conn, dial bool) (net.Conn, error) {
	c := e.Config
	s := c.Stealth
	stealth := record.Stealth{PaddingEnabled: s.PaddingEnabled, PaddingMin: s.PaddingMin, PaddingMax: s.PaddingMax, JitterEnabled: s.JitterEnabled, JitterMinMS: s.JitterMinMs, JitterMaxMS: s.JitterMaxMs, JitterLimitBytes: 64 << 10}
	if c.Encryption.Enabled {
		key, err := baseKey(c)
		if err != nil {
			return nil, err
		}
		if !e.Legacy {
			key, err = freshKey(conn, key, dial)
			if err != nil {
				return nil, err
			}
		}
		parity := uint8(0)
		// The v3 dial helper always sends even counters; its listener sends
		// odd counters. Direct mode reverses their public client/server roles.
		if (e.Legacy && !dial) || (!e.Legacy && c.Mode == "server") {
			parity = 1
		}
		return record.NewEncrypted(conn, key, c.Encryption.Algorithm, parity, stealth)
	}
	if s.PaddingEnabled || s.JitterEnabled {
		return record.NewPadded(conn, stealth)
	}
	return conn, nil
}
func (e *Engine) compression(conn net.Conn) (net.Conn, error) {
	z := e.Config.Compression
	if z.Enabled && !(e.Legacy && e.Config.Encryption.Enabled) {
		x, err := record.NewCompressed(conn, record.CompressionOptions{Enabled: true, Algorithm: z.Algorithm, Level: z.Level, MinSize: z.MinSize, MaxSize: z.MaxSize})
		if err != nil {
			return nil, err
		}
		return &chunkedConn{Conn: x, max: z.MaxSize}, nil
	}
	return conn, nil
}
func (e *Engine) session(conn net.Conn, dial bool, role string) error {
	conn.SetDeadline(time.Now().Add(time.Duration(e.Config.DialTimeout) * time.Second))
	wrapped, err := e.crypto(conn, dial)
	if err != nil {
		return err
	}
	reader := bufio.NewReaderSize(wrapped, 4096)
	hello := wire.Hello{Role: "ports", Mux: e.Config.SMUX.MuxCon}
	if dial {
		if role != "ports" && role != "tun" {
			return errors.New("invalid local session role")
		}
		hello.Role = role
	}
	if dial {
		err = wire.WriteHello(wrapped, e.Config.PSK, hello.Role, hello.Mux)
	} else {
		hello, err = wire.ReadHello(reader, e.Config.PSK)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Time{})
	wrapped = &bufferedConn{wrapped, reader}
	wrapped, err = e.compression(wrapped)
	if err != nil {
		return err
	}
	cfg := smuxConfig(e.Config)
	newSession := smux.Server
	if dial {
		newSession = smux.Client
	}
	outer, err := newSession(wrapped, cfg)
	if err != nil {
		return err
	}
	if !e.own(outer) {
		return e.ctx.Err()
	}
	defer e.release(outer)
	defer outer.Close()
	if hello.Mux <= 1 {
		e.addSession(outer, hello.Role)
		select {
		case <-outer.CloseChan():
		case <-e.ctx.Done():
		}
		return nil
	}
	if dial {
		for i := 0; i < hello.Mux; i++ {
			stream, err := outer.OpenStream()
			if err != nil {
				return err
			}
			innerConn := net.Conn(stream)
			innerConn, err = e.compression(innerConn)
			if err != nil {
				stream.Close()
				return err
			}
			inner, err := smux.Client(innerConn, cfg)
			if err != nil {
				stream.Close()
				return err
			}
			e.addSession(inner, hello.Role)
		}
		for {
			unexpected, err := outer.AcceptStream()
			if err != nil {
				return err
			}
			unexpected.Close()
		}
	}
	for {
		stream, err := outer.AcceptStream()
		if err != nil {
			return err
		}
		innerConn, err := e.compression(stream)
		if err != nil {
			stream.Close()
			return err
		}
		inner, err := smux.Server(innerConn, cfg)
		if err != nil {
			stream.Close()
			return err
		}
		e.addSession(inner, hello.Role)
	}
}
func (e *Engine) addSession(s *smux.Session, role string) {
	if role == "tun" {
		e.tunPool.add(s)
		e.startTUNStreams(s)
	} else {
		e.ports.add(s)
	}
	e.spawn(func() {
		defer s.Close()
		for {
			stream, err := s.AcceptStream()
			if err != nil {
				return
			}
			e.streams.Add(1)
			e.spawn(func() { defer e.streams.Add(-1); defer stream.Close(); e.handleStream(stream) })
		}
	})
}

// Compression bounds apply to each record, rather than the entire SMUX write.
type chunkedConn struct {
	net.Conn
	max int
}

func (c *chunkedConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), c.max)
		sent, err := c.Conn.Write(p[:n])
		total += sent
		if err != nil {
			return total, err
		}
		if sent != n {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}
