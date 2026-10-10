//go:build linux

// Independent Ethernet/raw KCP reconstruction by t.me/ir_spoof.
package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/xtaci/kcp-go/v5"
	"net"
	"netrix.local/ir_spoof/internal/config"
	"netrix.local/ir_spoof/internal/packet"
	"strconv"
)

func rawOptions(c *config.Config, p config.Path, listen bool) (packet.Options, *config.RawSocket, error) {
	r := p.Rawsocket
	if r == nil {
		r = c.Rawsocket
	}
	if r == nil {
		return packet.Options{}, nil, errors.New("rawsocket requires an interface and local/peer IPv4")
	}
	o := packet.Options{Carrier: "tcp", RawTCP: true, Interface: r.Interface, LocalIP: net.ParseIP(r.LocalIP), PeerIP: net.ParseIP(r.PeerIP), MTU: r.MTU, SocketBuffer: r.SockBuf}
	if o.MTU == 0 {
		o.MTU = 1450
	}
	if o.SocketBuffer == 0 {
		o.SocketBuffer = c.Advanced.UDPReadBuffer
	}
	var err error
	if r.RouterMac != "" {
		o.RouterMAC, err = net.ParseMAC(r.RouterMac)
		if err != nil {
			return o, r, errors.New("invalid rawsocket next-hop MAC")
		}
	}
	if len(r.LocalFlags) > 0 {
		o.LocalFlagCycle, err = packet.ParseTCPFlagCycle(r.LocalFlags)
	}
	if err != nil {
		return o, r, err
	}
	if len(r.RemoteFlags) > 0 {
		o.RemoteFlagCycle, err = packet.ParseTCPFlagCycle(r.RemoteFlags)
	}
	if err != nil {
		return o, r, err
	}
	_, port, err := net.SplitHostPort(p.Addr)
	if err != nil {
		return o, r, errors.New("rawsocket endpoint needs host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return o, r, errors.New("invalid rawsocket endpoint port")
	}
	if listen {
		o.LocalPort = n
		o.PeerPortAny = true
	} else {
		o.PeerPort = n
		var b [2]byte
		if _, err = rand.Read(b[:]); err != nil {
			return o, r, err
		}
		o.LocalPort = 1024 + int(binary.BigEndian.Uint16(b[:]))%50000
	}
	if o.Interface == "" || o.LocalIP.To4() == nil || o.PeerIP.To4() == nil {
		return o, r, errors.New("rawsocket needs an interface and literal IPv4 peers")
	}
	if o.MTU < 248 || o.MTU > 1500 || r.SndWnd < 0 || r.RcvWnd < 0 || r.SndWnd > 1<<20 || r.RcvWnd > 1<<20 || r.DataShard < 0 || r.ParityShard < 0 || r.DataShard+r.ParityShard > 255 {
		return o, r, errors.New("rawsocket tuning exceeds bounds")
	}
	o.TCPSequence, o.TCPAck = 1, 1
	_, err = packet.NewCodec(o)
	return o, r, err
}
func tuneRaw(x *kcp.UDPSession, c *config.Config, r *config.RawSocket, mtu int) {
	tuneKCP(x, c)
	snd, rcv := r.SndWnd, r.RcvWnd
	if snd == 0 {
		snd = c.KCP.Sndwnd
	}
	if rcv == 0 {
		rcv = c.KCP.Rcvwnd
	}
	x.SetWindowSize(snd, rcv)
	x.SetMtu(mtu - 48)
}
func dialRaw(ctx context.Context, c *config.Config, p config.Path) (net.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	o, r, err := rawOptions(c, p, false)
	if err != nil {
		return nil, err
	}
	socket, err := packet.Listen(o)
	if err != nil {
		return nil, err
	}
	peer, err := packet.PeerAddr(o)
	if err != nil {
		socket.Close()
		return nil, err
	}
	data, parity := r.DataShard, r.ParityShard
	if data == 0 && parity == 0 {
		data, parity = c.KCP.DataShard, c.KCP.ParityShard
	}
	x, err := newRawSession(peer, data, parity, socket)
	if err != nil {
		socket.Close()
		return nil, err
	}
	tuneRaw(x, c, r, o.MTU)
	return x, nil
}

type rawListener struct {
	*kcp.Listener
	socket net.PacketConn
	c      *config.Config
	r      *config.RawSocket
	mtu    int
}

func (l *rawListener) Accept() (net.Conn, error) {
	x, err := l.AcceptKCP()
	if err == nil {
		tuneRaw(x, l.c, l.r, l.mtu)
	}
	return x, err
}
func (l *rawListener) Close() error {
	err := l.Listener.Close()
	return errors.Join(err, l.socket.Close())
}
func listenRaw(ctx context.Context, c *config.Config, addr string) (net.Listener, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	o, r, err := rawOptions(c, config.Path{Addr: addr, Rawsocket: c.Rawsocket}, true)
	if err != nil {
		return nil, err
	}
	socket, err := packet.Listen(o)
	if err != nil {
		return nil, err
	}
	data, parity := r.DataShard, r.ParityShard
	if data == 0 && parity == 0 {
		data, parity = c.KCP.DataShard, c.KCP.ParityShard
	}
	l, err := kcp.ServeConn(nil, data, parity, socket)
	if err != nil {
		socket.Close()
		return nil, err
	}
	return &rawListener{l, socket, c, r, o.MTU}, nil
}

// ValidateRaw checks addresses and bounds without opening sockets or inspecting
// the host's interface names. Interface/MAC reachability is a runtime check.
func ValidateRaw(c *config.Config) error {
	if kind(c.Transport) == "rawsocket" && c.Mode == "server" && !c.Direct {
		_, _, err := rawOptions(c, config.Path{Addr: c.Listen}, true)
		if err != nil {
			return err
		}
	}
	if kind(c.Transport) == "rawsocket" && c.Mode == "client" && c.Direct {
		_, _, err := rawOptions(c, config.Path{Addr: c.Listen}, true)
		if err != nil {
			return err
		}
	}
	for _, p := range c.Paths {
		if kind(p.Transport) == "rawsocket" {
			_, _, err := rawOptions(c, p, false)
			if err != nil {
				return err
			}
		}
	}
	if kind(c.Transport) == "rawsocket" && c.Direct && c.Mode == "server" {
		_, _, err := rawOptions(c, config.Path{Addr: c.Connect}, false)
		return err
	}
	return nil
}
