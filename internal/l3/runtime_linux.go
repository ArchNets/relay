//go:build linux

// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"netrix.local/ir_spoof/internal/config"
	"netrix.local/ir_spoof/internal/firewall"
	"netrix.local/ir_spoof/internal/packet"
	"netrix.local/ir_spoof/internal/tun"
)

type carrier interface {
	ReadRecord() ([]byte, error)
	WriteRecord([]byte) error
	Close() error
}

type datagramCarrier struct {
	net.PacketConn
	peer net.Addr
}

func (d *datagramCarrier) ReadRecord() ([]byte, error) {
	buffer := make([]byte, maximumRecordSize)
	n, _, err := d.ReadFrom(buffer)
	return buffer[:n], err
}
func (d *datagramCarrier) WriteRecord(frame []byte) error {
	n, err := d.WriteTo(frame, d.peer)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}

type streamCarrier struct {
	net.Conn
	mu      sync.Mutex
	timeout time.Duration
}

func (s *streamCarrier) ReadRecord() ([]byte, error) { return ReadStreamRecord(s.Conn) }
func (s *streamCarrier) WriteRecord(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	return WriteStreamRecord(s.Conn, frame)
}

func openCarrier(ctx context.Context, c *config.Config, s *settings) (carrier, error) {
	if s.scope.Carrier != "tcp" {
		conn, err := packet.Listen(s.packet)
		if err != nil {
			return nil, err
		}
		return &datagramCarrier{PacketConn: conn, peer: &net.UDPAddr{IP: s.packet.PeerIP, Port: s.scope.PeerPort}}, nil
	}
	local := &net.TCPAddr{IP: s.packet.LocalIP, Port: s.scope.LocalPort}
	peer := &net.TCPAddr{IP: s.packet.PeerIP, Port: s.scope.PeerPort}
	var conn *net.TCPConn
	if c.Mode == "server" {
		listener, err := net.ListenTCP("tcp4", local)
		if err != nil {
			return nil, err
		}
		defer listener.Close()
		stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stop()
		for {
			candidate, err := listener.AcceptTCP()
			if err != nil {
				return nil, err
			}
			remote, ok := candidate.RemoteAddr().(*net.TCPAddr)
			if !ok || !remote.IP.Equal(peer.IP) {
				_ = candidate.Close()
				continue
			}
			conn = candidate
			break
		}
	} else {
		// TCP's local port is not part of record admission; the stable configured
		// port pair still participates in the SID and key context on both peers.
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: local.IP}, Timeout: s.timeout, KeepAlive: s.interval}
		connected, err := dialer.DialContext(ctx, "tcp4", peer.String())
		if err != nil {
			return nil, err
		}
		var ok bool
		conn, ok = connected.(*net.TCPConn)
		if !ok {
			_ = connected.Close()
			return nil, errors.New("l3: unexpected stream socket")
		}
	}
	if err := conn.SetNoDelay(true); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if s.readBuffer > 0 {
		if err := conn.SetReadBuffer(s.readBuffer); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if s.writeBuffer > 0 {
		if err := conn.SetWriteBuffer(s.writeBuffer); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return &streamCarrier{Conn: conn, timeout: s.timeout}, nil
}

type runtimeStatus struct {
	lastReceive              atomic.Int64
	received, sent, rejected atomic.Uint64
	dataVerified             atomic.Bool
}

var errReconnect = errors.New("l3: TCP session needs reconnection")

func healthListener(ctx context.Context, port int, timeout time.Duration, status *runtimeStatus) (io.Closer, error) {
	if port == 0 {
		return nil, nil
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	response := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		last := status.lastReceive.Load()
		if last == 0 || time.Since(time.Unix(0, last)) > timeout {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "peer not ready\n")
			return
		}
		_, _ = fmt.Fprintf(w, "ready\nreceived=%d sent=%d rejected=%d\n", status.received.Load(), status.sent.Load(), status.rejected.Load())
	}
	mux.HandleFunc("/health", response)
	mux.HandleFunc("/ready", response)
	mux.HandleFunc("/healthz", response)
	mux.HandleFunc("/readyz", response)
	mux.HandleFunc("/health/detailed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		last := status.lastReceive.Load()
		ready := last != 0 && time.Since(time.Unix(0, last)) <= timeout
		state, sessions := "disconnected", 0
		if ready {
			state = "healthy"
			sessions = 1
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": state, "ready": ready, "sessions": sessions, "streams": sessions, "peer_data_verified": status.dataVerified.Load() && ready, "packets_received": status.received.Load(), "packets_sent": status.sent.Load(), "packets_rejected": status.rejected.Load()})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	context.AfterFunc(ctx, func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	return server, nil
}

// Run carries complete TUN IP packets directly in recovered NL3X records.
// No vendor registration, IP discovery, telemetry or shared-host firewall
// commands run here. All interfaces and listeners are owned by this invocation.
func Run(ctx context.Context, c *config.Config, logger *log.Logger) error {
	if err := Validate(c); err != nil {
		return err
	}
	retry := time.Duration(c.RetryInterval) * time.Second
	if retry <= 0 {
		retry = 3 * time.Second
	}
	if retry > time.Hour {
		return errors.New("l3: retry interval exceeds limit")
	}
	for {
		err := runOnce(ctx, c, logger)
		if ctx.Err() != nil {
			return nil
		}
		if !errors.Is(err, errReconnect) {
			return err
		}
		if logger != nil {
			logger.Print("ir_spoof L3 TCP session disconnected; retrying")
		}
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runOnce(ctx context.Context, c *config.Config, logger *log.Logger) error {
	s, err := loadSettings(c)
	if err != nil {
		return err
	}
	sid, err := s.scope.SessionID()
	if err != nil {
		return err
	}
	key, algorithm, err := s.scope.DeriveKey(sid)
	if err != nil {
		return err
	}
	var crypto *Cipher
	if s.scope.Encrypted {
		crypto, err = NewCipher(key, algorithm, nil)
		if err != nil {
			return err
		}
	}
	encoder, err := NewEncoder(sid, crypto, nil)
	if err != nil {
		return err
	}
	decoder := &Decoder{SessionID: sid, Cipher: crypto}
	reassembly := new(Reassembler)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	device, err := tun.Open(s.name, s.local, s.mtu, s.queues, s.routes)
	if err != nil {
		return err
	}
	defer device.Close()
	if s.forward != nil {
		rules, err := firewall.Install(ctx, *s.forward)
		if err != nil {
			return err
		}
		defer rules.Close()
	}
	status := new(runtimeStatus)
	health, err := healthListener(ctx, s.healthPort, s.timeout, status)
	if err != nil {
		return err
	}
	if health != nil {
		defer health.Close()
	}
	conn, err := openCarrier(ctx, c, s)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.scope.Carrier == "tcp" && c.Mode == "client" {
			return errors.Join(errReconnect, err)
		}
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = device.Close() })
	defer stop()
	if logger != nil {
		logger.Printf("ir_spoof L3 TUN ready: carrier=%s encryption=%t", s.scope.Carrier, s.scope.Encrypted)
	}
	closers, err := startMappings(ctx, s.mappings)
	if err != nil {
		return err
	}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()
	errorsCh := make(chan error, s.queues+2)
	var workers sync.WaitGroup
	launch := func(task func() error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := task()
			if err != nil && ctx.Err() == nil {
				select {
				case errorsCh <- err:
				default:
				}
			}
		}()
	}
	outbound := make(chan []byte, s.channelSize)
	for i := 0; i < s.queues; i++ {
		queue := device.Queue(i)
		launch(func() error {
			buffer := make([]byte, MaximumPayload)
			for {
				n, err := queue.Read(buffer)
				if err != nil {
					return err
				}
				packet := append([]byte(nil), buffer[:n]...)
				select {
				case outbound <- packet:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
	}
	launch(func() error {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		write := func(frame []byte) error {
			if err := conn.WriteRecord(frame); err != nil {
				return err
			}
			status.sent.Add(1)
			return nil
		}
		// Send a sequenced empty control record immediately so both peers can
		// establish local readiness without waiting for user traffic.
		heartbeat := func() error {
			frame, err := encoder.Encode(nil, FlagControl)
			if err != nil {
				return err
			}
			return write(frame)
		}
		if err := heartbeat(); err != nil {
			return err
		}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				last := status.lastReceive.Load()
				if last != 0 && time.Since(time.Unix(0, last)) > s.timeout {
					return errors.New("l3: peer heartbeat timed out")
				}
				if err := heartbeat(); err != nil {
					return err
				}
			case packet := <-outbound:
				for batch := 0; ; batch++ {
					frames, err := encoder.EncodePacket(packet, s.fragmentSize)
					if err != nil {
						return err
					}
					for _, frame := range frames {
						if err := write(frame); err != nil {
							return err
						}
					}
					if batch+1 >= min(s.batchSize, 256) {
						break
					}
					select {
					case packet = <-outbound:
					default:
						packet = nil
					}
					if packet == nil {
						break
					}
				}
			}
		}
	})
	launch(func() error {
		for {
			frame, err := conn.ReadRecord()
			if err != nil {
				return err
			}
			h, payload, err := decoder.Decode(frame)
			if err != nil {
				status.rejected.Add(1)
				continue
			}
			// A reference unsequenced probe is intentionally unauthenticated;
			// it cannot renew peer health or place anything into the TUN.
			if h.Sequence == 0 {
				continue
			}
			status.received.Add(1)
			status.lastReceive.Store(time.Now().UnixNano())
			if h.Flags&FlagControl != 0 {
				if len(payload) != 0 {
					status.rejected.Add(1)
				}
				continue
			}
			payload, err = reassembly.Add(h, payload, time.Now())
			if err != nil {
				status.rejected.Add(1)
				continue
			}
			if payload == nil {
				continue
			}
			if len(payload) > s.mtu {
				status.rejected.Add(1)
				continue
			}
			if _, err := device.Queue(0).Write(payload); err != nil {
				return err
			}
			status.dataVerified.Store(true)
		}
	})
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errorsCh:
	}
	cancel()
	_ = conn.Close()
	_ = device.Close()
	workers.Wait()
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	if s.scope.Carrier == "tcp" {
		return errors.Join(errReconnect, err)
	}
	return err
}
