// Independent Linux reconstruction by t.me/ir_spoof.
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	kcp "github.com/xtaci/kcp-go/v5"
	"netrix.local/ir_spoof/internal/config"
)

type Options struct {
	Config *config.Config
	Path   config.Path
}

func kind(s string) string {
	switch s {
	case "tcp":
		return "tcpmux"
	case "tls":
		return "tlsmux"
	case "kcp":
		return "kcpmux"
	case "ws":
		return "wsmux"
	case "wss":
		return "wssmux"
	case "rawmux":
		return "rawsocket"
	}
	return s
}

func Dial(ctx context.Context, o Options) (net.Conn, error) {
	p, c := o.Path, o.Config
	k := kind(p.Transport)
	timeout := time.Duration(p.DialTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{Timeout: timeout, KeepAlive: time.Duration(c.Advanced.TCPKeepalive) * time.Second}
	if k == "rawsocket" {
		return dialRaw(ctx, c, p)
	}
	if k == "kcpmux" {
		type result struct {
			c *kcp.UDPSession
			e error
		}
		ch := make(chan result)
		go func() {
			x, e := kcp.DialWithOptions(p.Addr, nil, c.KCP.DataShard, c.KCP.ParityShard)
			select {
			case ch <- result{x, e}:
			case <-ctx.Done():
				if x != nil {
					x.Close()
				}
			}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-ch:
			if r.e != nil {
				return nil, r.e
			}
			tuneKCP(r.c, c)
			return r.c, nil
		}
	}
	if k == "wsmux" || k == "wssmux" {
		address := p.Addr
		scheme := "ws"
		if k == "wssmux" {
			scheme = "wss"
		}
		// The recovered v3 listener registers /ws for both WS carriers.
		path := "/ws"
		if strings.Contains(address, "://") {
			return nil, errors.New("path addr must be host:port")
		}
		tc, e := clientTLS(c, p)
		if e != nil {
			return nil, e
		}
		wd := websocket.Dialer{HandshakeTimeout: timeout, ReadBufferSize: c.Advanced.WebsocketReadBuffer, WriteBufferSize: c.Advanced.WebsocketWriteBuffer, TLSClientConfig: tc, EnableCompression: c.Advanced.WebsocketCompression != nil && *c.Advanced.WebsocketCompression}
		wd.NetDialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
			if p.EdgeIP != "" {
				host, port, e := net.SplitHostPort(a)
				_ = host
				if e != nil {
					return nil, e
				}
				a = net.JoinHostPort(p.EdgeIP, port)
			}
			x, e := d.DialContext(ctx, n, a)
			if e == nil {
				tuneTCP(x, c)
			}
			return x, e
		}
		x, r, e := wd.DialContext(ctx, scheme+"://"+address+path, nil)
		if r != nil && r.Body != nil {
			r.Body.Close()
		}
		if e != nil {
			return nil, e
		}
		return newWS(x), nil
	}
	if k != "tcpmux" && k != "tlsmux" && k != "realitymux" {
		return nil, errors.New("transport requires its Linux packet implementation")
	}
	address := p.Addr
	if p.EdgeIP != "" {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		address = net.JoinHostPort(p.EdgeIP, port)
	}
	conn, e := d.DialContext(ctx, "tcp", address)
	if e != nil {
		return nil, e
	}
	tuneTCP(conn, c)
	if k == "tcpmux" {
		return conn, nil
	}
	tc, e := clientTLS(c, p)
	if e != nil {
		conn.Close()
		return nil, e
	}
	if k == "tlsmux" {
		x := tls.Client(conn, tc)
		if e = x.HandshakeContext(ctx); e != nil {
			conn.Close()
			return nil, e
		}
		return x, nil
	}
	fingerprint := "chrome"
	if p.Reality != nil && p.Reality.Fingerprint != "" {
		fingerprint = strings.ToLower(p.Reality.Fingerprint)
	} else if c.Reality != nil && c.Reality.Fingerprint != "" {
		fingerprint = strings.ToLower(c.Reality.Fingerprint)
	}
	id := utls.HelloChrome_Auto
	switch fingerprint {
	case "chrome":
	case "firefox":
		id = utls.HelloFirefox_Auto
	case "safari":
		id = utls.HelloSafari_Auto
	case "edge":
		id = utls.HelloEdge_Auto
	case "randomized":
		id = utls.HelloRandomized
	default:
		conn.Close()
		return nil, errors.New("unsupported browser fingerprint")
	}
	x := utls.UClient(conn, &utls.Config{ServerName: tc.ServerName, RootCAs: tc.RootCAs, InsecureSkipVerify: tc.InsecureSkipVerify, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}, id)
	if e = x.HandshakeContext(ctx); e != nil {
		conn.Close()
		return nil, e
	}
	return x, nil
}

func clientTLS(c *config.Config, p config.Path) (*tls.Config, error) {
	host, _, e := net.SplitHostPort(p.Addr)
	if e != nil {
		return nil, e
	}
	sni := host
	if c.Reality != nil && c.Reality.SNI != "" {
		sni = c.Reality.SNI
	}
	if p.Reality != nil && p.Reality.SNI != "" {
		sni = p.Reality.SNI
	}
	tc := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	tc.InsecureSkipVerify = c.Advanced.TLSInsecureSkipVerify != nil && *c.Advanced.TLSInsecureSkipVerify
	if c.CAFile != "" {
		data, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, errors.New("cannot read local trust certificate")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid local trust certificate")
		}
		tc.RootCAs = roots
	}
	// Verification and all socket destinations are local configuration decisions.
	// Go TLS does not fetch certificate issuers or perform automatic OCSP requests.
	return tc, nil
}

func Listen(ctx context.Context, c *config.Config, addr, carrier string) (net.Listener, error) {
	k := kind(carrier)
	if k == "rawsocket" {
		return listenRaw(ctx, c, addr)
	}
	if k == "kcpmux" {
		l, e := kcp.ListenWithOptions(addr, nil, c.KCP.DataShard, c.KCP.ParityShard)
		if e != nil {
			return nil, e
		}
		l.SetReadBuffer(c.Advanced.UDPReadBuffer)
		l.SetWriteBuffer(c.Advanced.UDPWriteBuffer)
		return &kcpListener{l, c}, nil
	}
	if k != "tcpmux" && k != "tlsmux" && k != "realitymux" && k != "wsmux" && k != "wssmux" {
		return nil, errors.New("transport requires its Linux packet implementation")
	}
	lc := net.ListenConfig{KeepAlive: time.Duration(c.Advanced.TCPKeepalive) * time.Second}
	l, e := lc.Listen(ctx, "tcp", addr)
	if e != nil {
		return nil, e
	}
	if k == "tlsmux" || k == "realitymux" || k == "wssmux" {
		cert, e := serverCert(c)
		if e != nil {
			l.Close()
			return nil, e
		}
		tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		if k == "realitymux" {
			tc.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				clone := tc.Clone()
				clone.GetConfigForClient = nil
				clone.CipherSuites = append([]uint16(nil), hello.CipherSuites...)
				clone.CurvePreferences = append([]tls.CurveID(nil), hello.SupportedCurves...)
				return clone, nil
			}
		}
		l = tls.NewListener(l, tc)
	}
	if k == "wsmux" || k == "wssmux" {
		return newWSListener(l, c), nil
	}
	return &tcpListener{l, c}, nil
}
func serverCert(c *config.Config) (tls.Certificate, error) {
	if c.CertFile != "" {
		cert, e := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if e != nil {
			return tls.Certificate{}, errors.New("cannot read TLS certificate and key")
		}
		return cert, nil
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return tls.Certificate{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return tls.Certificate{}, e
	}
	now := time.Now()
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "netrix ir_spoof"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if e != nil {
		return tls.Certificate{}, e
	}
	private, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		return tls.Certificate{}, e
	}
	return tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
}
func tuneTCP(x net.Conn, c *config.Config) {
	if t, ok := x.(*net.TCPConn); ok {
		if c.Advanced.TCPNodelay != nil {
			t.SetNoDelay(*c.Advanced.TCPNodelay)
		}
		t.SetReadBuffer(c.Advanced.TCPReadBuffer)
		t.SetWriteBuffer(c.Advanced.TCPWriteBuffer)
	}
}
func tuneKCP(x *kcp.UDPSession, c *config.Config) {
	k := c.KCP
	x.SetWindowSize(k.Sndwnd, k.Rcvwnd)
	x.SetNoDelay(k.Nodelay, k.Interval, k.Resend, k.Nc)
	x.SetMtu(k.MTU)
	x.SetACKNoDelay(true)
	x.SetStreamMode(true)
	x.SetReadBuffer(c.Advanced.UDPReadBuffer)
	x.SetWriteBuffer(c.Advanced.UDPWriteBuffer)
}

type tcpListener struct {
	net.Listener
	c *config.Config
}

func (l *tcpListener) Accept() (net.Conn, error) {
	x, e := l.Listener.Accept()
	if e == nil {
		tuneTCP(x, l.c)
	}
	return x, e
}

type kcpListener struct {
	*kcp.Listener
	c *config.Config
}

func (l *kcpListener) Accept() (net.Conn, error) {
	x, e := l.AcceptKCP()
	if e == nil {
		tuneKCP(x, l.c)
	}
	return x, e
}

type wsConn struct {
	*websocket.Conn
	read   sync.Mutex
	write  sync.Mutex
	reader io.Reader
}

func newWS(x *websocket.Conn) net.Conn { x.SetReadLimit(4 << 20); return &wsConn{Conn: x} }
func (w *wsConn) Read(p []byte) (int, error) {
	w.read.Lock()
	defer w.read.Unlock()
	for {
		if w.reader == nil {
			typ, r, e := w.NextReader()
			if e != nil {
				return 0, e
			}
			if typ != websocket.BinaryMessage {
				return 0, errors.New("expected binary WebSocket message")
			}
			w.reader = r
		}
		n, e := w.reader.Read(p)
		if e == io.EOF {
			w.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, e
	}
}
func (w *wsConn) Write(p []byte) (int, error) {
	w.write.Lock()
	defer w.write.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if e := w.WriteMessage(websocket.BinaryMessage, p); e != nil {
		return 0, e
	}
	return len(p), nil
}
func (w *wsConn) LocalAddr() net.Addr           { return w.UnderlyingConn().LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr          { return w.UnderlyingConn().RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error { return w.UnderlyingConn().SetDeadline(t) }

type wsListener struct {
	net.Listener
	server *http.Server
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newWSListener(l net.Listener, c *config.Config) net.Listener {
	w := &wsListener{Listener: l, accept: make(chan net.Conn, 64), closed: make(chan struct{})}
	upgrader := websocket.Upgrader{ReadBufferSize: c.Advanced.WebsocketReadBuffer, WriteBufferSize: c.Advanced.WebsocketWriteBuffer, EnableCompression: c.Advanced.WebsocketCompression != nil && *c.Advanced.WebsocketCompression}
	w.server = &http.Server{ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16384, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(rw, r)
			return
		}
		x, e := upgrader.Upgrade(rw, r, nil)
		if e != nil {
			return
		}
		select {
		case w.accept <- newWS(x):
		case <-w.closed:
			x.Close()
		}
	})}
	go func() { w.server.Serve(l); w.Close() }()
	return w
}
func (w *wsListener) Accept() (net.Conn, error) {
	select {
	case x := <-w.accept:
		return x, nil
	case <-w.closed:
		return nil, net.ErrClosed
	}
}
func (w *wsListener) Close() error {
	w.once.Do(func() {
		close(w.closed)
		w.Listener.Close()
		w.server.Close()
		for {
			select {
			case x := <-w.accept:
				x.Close()
			default:
				return
			}
		}
	})
	return nil
}
