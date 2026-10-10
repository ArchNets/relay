//go:build linux

// Independent Linux reconstruction by t.me/ir_spoof.
package core

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
	"netrix.local/ir_spoof/internal/config"
	"netrix.local/ir_spoof/internal/wire"
)

func itoa(n int) string { return strconv.Itoa(n) }
func (e *Engine) forward(m config.Mapping) error {
	if m.Type == "tcp" {
		l, err := net.Listen("tcp", m.Bind)
		if err != nil {
			return errors.New("cannot bind TCP forwarding port")
		}
		e.own(l)
		e.spawn(func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				if !e.own(c) {
					return
				}
				e.spawn(func() {
					defer func() { c.Close(); e.release(c) }()
					s, err := e.ports.open(e.ctx)
					if err != nil {
						return
					}
					defer s.Close()
					head := "CONNECT " + m.Target
					if e.proxyFor(m.Target) != "" {
						head += " X-Real-IP:" + c.RemoteAddr().String()
					}
					if wire.WriteAll(s, []byte(head+"\n")) != nil {
						return
					}
					bridge(c, s)
				})
			}
		})
		return nil
	}
	return e.forwardUDP(m)
}
func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyTo := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			a.Close()
			b.Close()
		} else if half, ok := dst.(interface{ CloseWrite() error }); ok {
			if half.CloseWrite() != nil {
				a.Close()
				b.Close()
			}
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go copyTo(a, b)
	go copyTo(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}
func (e *Engine) handleStream(s *smux.Stream) {
	s.SetReadDeadline(time.Now().Add(time.Duration(e.Config.DialTimeout) * time.Second))
	r := bufio.NewReader(s)
	line, err := wire.Line(r, 512)
	if err != nil {
		return
	}
	s.SetReadDeadline(time.Time{})
	fields := strings.Fields(line)
	if len(fields) == 1 && fields[0] == "CTRL" {
		replyControl(e.ctx, s, r, controlIdleTimeout)
		return
	}
	if len(fields) < 2 {
		return
	}
	switch fields[0] {
	case "CONNECT":
		e.targetTCP(&bufferedConn{s, r}, fields)
	case "UDP":
		e.targetUDP(&bufferedConn{s, r}, fields[1])
	case "TUN":
		e.receiveTUN(s, r, fields[1])
	}
}
func (e *Engine) targetTCP(stream net.Conn, fields []string) {
	d := net.Dialer{Timeout: time.Duration(e.Config.DialTimeout) * time.Second}
	conn, err := d.DialContext(e.ctx, "tcp", fields[1])
	if err != nil {
		return
	}
	if !e.own(conn) {
		return
	}
	defer func() { conn.Close(); e.release(conn) }()
	if version := e.proxyFor(fields[1]); version != "" {
		source := ""
		for _, f := range fields[2:] {
			if strings.HasPrefix(f, "X-Real-IP:") {
				source = strings.TrimPrefix(f, "X-Real-IP:")
			}
		}
		if writeProxy(conn, source, conn.RemoteAddr().String(), version) != nil {
			return
		}
	}
	bridge(conn, stream)
}
func (e *Engine) proxyFor(target string) string {
	p := e.Config.ProxyProtocol
	if p == nil || !p.Enabled {
		return ""
	}
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	if v, ok := p.Ports[port]; ok {
		if v == "" {
			v = "v1"
		}
		return v
	}
	if len(p.Ports) > 0 {
		return ""
	}
	if len(p.PortList) > 0 {
		for _, item := range p.PortList {
			if strings.TrimSpace(itoaAny(item)) == port {
				if p.Version == "" {
					return "v1"
				}
				return p.Version
			}
		}
		return ""
	}
	v := p.Version
	if v == "" {
		v = "v1"
	}
	return v
}
func itoaAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return itoa(x)
	case uint64:
		return strconv.FormatUint(x, 10)
	default:
		return ""
	}
}
func writeProxy(w io.Writer, source, dest, version string) error {
	sh, sp, err := net.SplitHostPort(source)
	dh, dp, err2 := net.SplitHostPort(dest)
	s, d := net.ParseIP(sh), net.ParseIP(dh)
	if err != nil || err2 != nil || s == nil || d == nil {
		if version == "v2" || version == "2" {
			return wire.WriteAll(w, append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x20, 0, 0, 0))
		}
		return wire.WriteAll(w, []byte("PROXY UNKNOWN\r\n"))
	}
	if version != "v2" && version != "2" {
		family := "TCP6"
		if s.To4() != nil && d.To4() != nil {
			family = "TCP4"
		}
		return wire.WriteAll(w, []byte("PROXY "+family+" "+sh+" "+dh+" "+sp+" "+dp+"\r\n"))
	}
	frame := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x21, 0, 36)
	if s.To4() != nil && d.To4() != nil {
		frame[13] = 0x11
		frame[15] = 12
		s, d = s.To4(), d.To4()
	} else {
		s, d = s.To16(), d.To16()
	}
	frame = append(frame, s...)
	frame = append(frame, d...)
	var ports [4]byte
	sn, _ := strconv.Atoi(sp)
	dn, _ := strconv.Atoi(dp)
	binary.BigEndian.PutUint16(ports[:2], uint16(sn))
	binary.BigEndian.PutUint16(ports[2:], uint16(dn))
	return wire.WriteAll(w, append(frame, ports[:]...))
}

// One ordered stream per UDP flow bounds state and keeps replies on the same
// original local socket. Addresses in frames are flow identifiers, never DNS.
type udpFlow struct {
	s    *smux.Stream
	last time.Time
	mu   sync.Mutex
}

func (e *Engine) forwardUDP(m config.Mapping) error {
	a, err := net.ResolveUDPAddr("udp", m.Bind)
	if err != nil {
		return errors.New("invalid UDP forwarding bind")
	}
	socket, err := net.ListenUDP("udp", a)
	if err != nil {
		return errors.New("cannot bind UDP forwarding port")
	}
	e.own(socket)
	var mu sync.Mutex
	flows := map[string]*udpFlow{}
	timeout := time.Duration(e.Config.Advanced.UDPFlowTimeout) * time.Second
	e.spawn(func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer func() {
			mu.Lock()
			defer mu.Unlock()
			for _, f := range flows {
				f.s.Close()
			}
		}()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				for k, f := range flows {
					if time.Since(f.last) > timeout {
						f.s.Close()
						delete(flows, k)
					}
				}
				mu.Unlock()
			}
		}
	})
	e.spawn(func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := socket.ReadFromUDP(buf)
			if err != nil {
				return
			}
			key := addr.String()
			mu.Lock()
			f := flows[key]
			if f == nil && len(flows) >= e.Config.Advanced.MaxUDPFlows {
				mu.Unlock()
				continue
			}
			mu.Unlock()
			if f == nil {
				s, err := e.ports.open(e.ctx)
				if err != nil {
					return
				}
				if wire.WriteAll(s, []byte("UDP "+m.Target+"\n")) != nil {
					s.Close()
					continue
				}
				f = &udpFlow{s: s, last: time.Now()}
				mu.Lock()
				flows[key] = f
				mu.Unlock()
				flow := f
				source := *addr
				e.spawn(func() {
					defer func() {
						flow.s.Close()
						mu.Lock()
						if flows[key] == flow {
							delete(flows, key)
						}
						mu.Unlock()
					}()
					for {
						_, data, err := wire.ReadUDP(flow.s)
						if err != nil {
							return
						}
						if _, err = socket.WriteToUDP(data, &source); err != nil {
							return
						}
					}
				})
			}
			mu.Lock()
			f.last = time.Now()
			mu.Unlock()
			f.mu.Lock()
			err = wire.WriteUDP(f.s, key, buf[:n])
			f.mu.Unlock()
			if err != nil {
				f.s.Close()
			}
		}
	})
	return nil
}
func (e *Engine) targetUDP(stream net.Conn, target string) {
	d := net.Dialer{Timeout: time.Duration(e.Config.DialTimeout) * time.Second}
	var mu sync.Mutex
	type flow struct{ conn net.Conn }
	flows := map[string]*flow{}
	writeMu := new(sync.Mutex)
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range flows {
			f.conn.Close()
		}
	}()
	for {
		key, data, err := wire.ReadUDP(stream)
		if err != nil {
			return
		}
		mu.Lock()
		f := flows[key]
		if f == nil && len(flows) >= e.Config.Advanced.MaxUDPFlows {
			mu.Unlock()
			continue
		}
		mu.Unlock()
		if f == nil {
			c, err := d.DialContext(e.ctx, "udp", target)
			if err != nil {
				continue
			}
			if !e.own(c) {
				return
			}
			f = &flow{c}
			mu.Lock()
			flows[key] = f
			mu.Unlock()
			flowKey := key
			flow := f
			e.spawn(func() {
				defer func() {
					flow.conn.Close()
					e.release(flow.conn)
					mu.Lock()
					if flows[flowKey] == flow {
						delete(flows, flowKey)
					}
					mu.Unlock()
				}()
				buf := make([]byte, 65535)
				for {
					flow.conn.SetReadDeadline(time.Now().Add(time.Duration(e.Config.Advanced.UDPFlowTimeout) * time.Second))
					n, err := flow.conn.Read(buf)
					if err != nil {
						return
					}
					writeMu.Lock()
					err = wire.WriteUDP(stream, flowKey, buf[:n])
					writeMu.Unlock()
					if err != nil {
						return
					}
				}
			})
		}
		f.conn.SetWriteDeadline(time.Now().Add(time.Duration(e.Config.DialTimeout) * time.Second))
		if _, err = f.conn.Write(data); err != nil {
			f.conn.Close()
		}
	}
}

func (e *Engine) startTUNStreams(_ *smux.Session) {
	if e.device == nil || e.Config.Mode != "server" {
		return
	}
	e.tunOnce.Do(func() {
		for i := 0; i < e.Config.Tun.Streams; i++ {
			index := i
			e.spawn(func() {
				for e.ctx.Err() == nil {
					s, err := e.tunPool.open(e.ctx)
					if err != nil {
						if !e.pause(100 * time.Millisecond) {
							return
						}
						continue
					}
					if wire.WriteAll(s, []byte("TUN "+itoa(index+1)+"/"+itoa(e.Config.Tun.Streams)+"\n")) != nil {
						s.Close()
						if !e.pause(100 * time.Millisecond) {
							return
						}
						continue
					}
					e.streams.Add(1)
					e.receiveTUN(s, s, itoa(index+1)+"/"+itoa(e.Config.Tun.Streams))
					e.streams.Add(-1)
					s.Close()
				}
			})
		}
	})
}
func (e *Engine) receiveTUN(conn io.ReadWriteCloser, r io.Reader, index string) {
	if e.device == nil || e.tunPackets == nil {
		return
	}
	slot, err := parseTUNSlot(index)
	if err != nil {
		return
	}
	stream, ok := e.tunPackets.register(slot, conn)
	if !ok {
		return
	}
	defer e.tunPackets.clear(slot, stream)
	_ = readTUNPackets(e.device.Queue(slot.index%e.Config.Tun.Streams), r)
}
