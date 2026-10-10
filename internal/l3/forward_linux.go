//go:build linux

// Local L3 tunnel forwarding by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"netrix.local/ir_spoof/internal/config"
)

// startMappings uses ordinary kernel routing to the remote TUN address. These
// listeners are local forwarding conveniences, not another NL3X wire protocol.
func startMappings(ctx context.Context, rows []config.Mapping) ([]io.Closer, error) {
	var closers []io.Closer
	limit := make(chan struct{}, 1024)
	cleanup := func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}
	for _, row := range rows {
		row := row
		if row.Type == "tcp" {
			listener, err := net.Listen("tcp", row.Bind)
			if err != nil {
				cleanup()
				return nil, err
			}
			closers = append(closers, listener)
			context.AfterFunc(ctx, func() { _ = listener.Close() })
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					select {
					case limit <- struct{}{}:
						go func() { defer func() { <-limit }(); forwardTCP(ctx, conn, row.Target) }()
					default:
						_ = conn.Close()
					}
				}
			}()
		} else {
			address, err := net.ResolveUDPAddr("udp", row.Bind)
			if err != nil {
				cleanup()
				return nil, err
			}
			listener, err := net.ListenUDP("udp", address)
			if err != nil {
				cleanup()
				return nil, err
			}
			target, err := net.ResolveUDPAddr("udp", row.Target)
			if err != nil {
				_ = listener.Close()
				cleanup()
				return nil, err
			}
			closers = append(closers, listener)
			context.AfterFunc(ctx, func() { _ = listener.Close() })
			go forwardUDP(ctx, listener, target, limit)
		}
	}
	return closers, nil
}

func forwardTCP(ctx context.Context, local net.Conn, target string) {
	defer local.Close()
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	remote, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer remote.Close()
	stop := context.AfterFunc(ctx, func() { _ = local.Close(); _ = remote.Close() })
	defer stop()
	var copyWorkers sync.WaitGroup
	copyHalf := func(dst, src net.Conn) {
		defer copyWorkers.Done()
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	copyWorkers.Add(2)
	go copyHalf(remote, local)
	go copyHalf(local, remote)
	copyWorkers.Wait()
}

type udpFlow struct {
	conn *net.UDPConn
	peer *net.UDPAddr
	last time.Time
}

func forwardUDP(ctx context.Context, listener *net.UDPConn, target *net.UDPAddr, limit chan struct{}) {
	var mu sync.Mutex
	flows := make(map[string]*udpFlow)
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, flow := range flows {
			_ = flow.conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, flow := range flows {
			_ = flow.conn.Close()
		}
	})
	defer stop()
	buffer := make([]byte, MaximumPayload)
	for {
		n, peer, err := listener.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		key := peer.String()
		mu.Lock()
		flow := flows[key]
		if flow == nil {
			select {
			case limit <- struct{}{}:
			default:
				mu.Unlock()
				continue
			}
			conn, err := net.DialUDP("udp", nil, target)
			if err != nil {
				<-limit
				mu.Unlock()
				continue
			}
			flow = &udpFlow{conn: conn, peer: peer, last: time.Now()}
			flows[key] = flow
			go func(flow *udpFlow) {
				defer func() {
					_ = flow.conn.Close()
					mu.Lock()
					if flows[key] == flow {
						delete(flows, key)
					}
					mu.Unlock()
					<-limit
				}()
				reply := make([]byte, MaximumPayload)
				for {
					mu.Lock()
					deadline := flow.last.Add(30 * time.Second)
					mu.Unlock()
					if err := flow.conn.SetReadDeadline(deadline); err != nil {
						return
					}
					n, err := flow.conn.Read(reply)
					if err != nil {
						var timeout net.Error
						if errors.As(err, &timeout) && timeout.Timeout() {
							mu.Lock()
							fresh := time.Since(flow.last) < 30*time.Second
							mu.Unlock()
							if fresh {
								continue
							}
						}
						return
					}
					if _, err := listener.WriteToUDP(reply[:n], flow.peer); err != nil {
						return
					}
				}
			}(flow)
		}
		flow.last = time.Now()
		mu.Unlock()
		_ = flow.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := flow.conn.Write(buffer[:n]); err != nil {
			_ = flow.conn.Close()
		}
	}
}
