//go:build linux

// Independent Linux reconstruction by t.me/ir_spoof.
package core

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"netrix.local/ir_spoof/internal/config"
	"netrix.local/ir_spoof/internal/firewall"
	"netrix.local/ir_spoof/internal/l3"
	"netrix.local/ir_spoof/internal/transport"
	"netrix.local/ir_spoof/internal/tun"
)

type Engine struct {
	Config         *config.Config
	Legacy         bool
	Logger         *log.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	ports, tunPool *pool
	device         *tun.Device
	tunOnce        sync.Once
	tunPackets     *tunPacketPool
	streams        atomic.Int64
	mu             sync.Mutex
	closers        []io.Closer
	closing        bool
	workers        sync.WaitGroup
}

func (e *Engine) own(c io.Closer) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		c.Close()
		return false
	}
	e.closers = append(e.closers, c)
	return true
}
func (e *Engine) release(c io.Closer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, x := range e.closers {
		if x == c {
			e.closers = append(e.closers[:i], e.closers[i+1:]...)
			return
		}
	}
}
func (e *Engine) close() {
	e.cancel()
	e.mu.Lock()
	e.closing = true
	items := e.closers
	e.closers = nil
	e.mu.Unlock()
	for _, c := range items {
		c.Close()
	}
	e.ports.close()
	e.tunPool.close()
	if e.tunPackets != nil {
		e.tunPackets.close()
	}
	if e.device != nil {
		e.device.Close()
	}
}
func (e *Engine) notice(s string) {
	if e.Logger != nil {
		e.Logger.Print(s)
	}
}
func (e *Engine) spawn(f func()) { e.workers.Add(1); go func() { defer e.workers.Done(); f() }() }
func (e *Engine) pause(d time.Duration) bool {
	select {
	case <-e.ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// Run creates only explicitly configured listeners, peer connections and routes.
// Status output deliberately excludes peer addresses, secrets and file paths.
func (e *Engine) Run(ctx context.Context) error {
	if e.Config == nil {
		return errors.New("missing configuration")
	}
	if err := e.Config.Validate(); err != nil {
		return err
	}
	if e.Config.Transport == "l3" {
		err := l3.Run(ctx, e.Config, e.Logger)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.ports, e.tunPool = newPool(), newPool()
	defer func() { e.close(); e.workers.Wait() }()
	c := e.Config
	if c.Tun != nil && c.Tun.Enabled {
		d, err := tun.Open(c.Tun.Name, c.Tun.Local, c.Tun.MTU, c.Tun.Streams, c.Tun.Routes)
		if err != nil {
			return err
		}
		e.device = d
		e.tunPackets = newTUNPacketPool(c.Tun.Streams)
		for i := 0; i < c.Tun.Streams; i++ {
			index, queue := i, d.Queue(i)
			e.spawn(func() { pumpTUNPackets(e.ctx, e.tunPackets, queue, index) })
		}
		if c.Tun.ForwardL2TP {
			owned, err := firewall.Install(e.ctx, firewall.Options{Interface: d.Name(), LocalCIDR: c.Tun.Local, Remote: c.Tun.Remote, Ports: c.Tun.L2TPPorts, Destination: c.Tun.L2TPDestIP})
			if err != nil {
				return err
			}
			e.own(owned)
		}
	}
	healthPort := c.HealthPort
	if healthPort == 0 && c.Tun != nil {
		healthPort = c.Tun.HealthPort
	}
	if healthPort > 0 {
		lc := net.ListenConfig{}
		l, err := lc.Listen(e.ctx, "tcp", net.JoinHostPort("127.0.0.1", itoa(healthPort)))
		if err != nil {
			return errors.New("cannot open local health listener")
		}
		e.own(l)
		s := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" && r.URL.Path != "/health/detailed" && r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"sessions":`+itoa(e.ports.count()+e.tunPool.count())+`,"streams":`+itoa(int(e.streams.Load()))+`,"channel":"ir_spoof"}`)
		})}
		e.spawn(func() { s.Serve(l) })
	}
	// Direct changes which peer establishes the carrier, not which public role
	// exposes forwarding ports. The server owns mappings in either direction.
	if c.Mode == "server" {
		maps, err := c.Mappings()
		if err != nil {
			return err
		}
		for _, m := range maps {
			if err = e.forward(m); err != nil {
				return err
			}
		}
	}
	dial := c.Mode == "client"
	if c.Direct {
		dial = !dial
	}
	if dial {
		paths := c.Paths
		if c.Direct {
			paths = []config.Path{{Transport: c.Transport, Addr: c.Connect, EdgeIP: c.EdgeIP, ConnectionPool: c.ConnectionPool, RetryInterval: c.RetryInterval, DialTimeout: c.DialTimeout, Reality: c.Reality, Rawsocket: c.Rawsocket}}
		}
		for _, p := range paths {
			for i := 0; i < p.ConnectionPool; i++ {
				path := p
				e.spawn(func() { e.dialLoop(path, "ports") })
				if e.device != nil {
					e.spawn(func() { e.dialLoop(path, "tun") })
				}
			}
		}
	} else {
		l, err := transport.Listen(e.ctx, c, c.Listen, c.Transport)
		if err != nil {
			return errors.New("cannot open configured transport listener")
		}
		e.own(l)
		e.spawn(func() { e.acceptLoop(l) })
	}
	e.notice("Netrix ir_spoof ready; local configuration only")
	<-e.ctx.Done()
	return nil
}
func (e *Engine) dialLoop(p config.Path, role string) {
	for e.ctx.Err() == nil {
		conn, err := transport.Dial(e.ctx, transport.Options{Config: e.Config, Path: p})
		if err == nil {
			if !e.own(conn) {
				return
			}
			err = e.session(conn, true, role)
			conn.Close()
			e.release(conn)
		}
		if e.ctx.Err() != nil {
			return
		}
		e.notice("peer session disconnected; retrying")
		if !e.pause(time.Duration(p.RetryInterval) * time.Second) {
			return
		}
	}
}
func (e *Engine) acceptLoop(l net.Listener) {
	limit := e.Config.Advanced.MaxConnections
	if limit <= 0 {
		limit = 1024
	}
	slots := make(chan struct{}, limit)
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		if !e.own(conn) {
			<-slots
			return
		}
		e.spawn(func() {
			defer func() { conn.Close(); e.release(conn); <-slots }()
			if err := e.session(conn, false, ""); err != nil && e.ctx.Err() == nil {
				e.notice("peer session ended or authentication failed")
			}
		})
	}
}
