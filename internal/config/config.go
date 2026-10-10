// Independent Linux reconstruction by t.me/ir_spoof.
package config

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Load accepts the observed YAML interface and JSON produced by the offline manager.
// Checking configuration never resolves a hostname, opens a socket or contacts a vendor.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open configuration")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	c := new(Config)
	if err = dec.Decode(c); err != nil {
		return nil, errors.New("invalid configuration syntax, field name or field type")
	}
	var extra any
	if err = dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("configuration must contain one document")
	}
	c.Defaults()
	if err = c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func boolPtr(v bool) *bool { return &v }
func positive(v *int, fallback int) {
	if *v == 0 {
		*v = fallback
	}
}

// Defaults retain the original manager's published balanced profile.
func (c *Config) Defaults() {
	if c.Profile == "" {
		c.Profile = "balanced"
	}
	if c.Transport == "" {
		c.Transport = "tcpmux"
	}
	positive(&c.ConnectionPool, 8)
	positive(&c.RetryInterval, 3)
	positive(&c.DialTimeout, 10)
	positive(&c.Heartbeat, 5)
	if c.Advanced == nil {
		c.Advanced = &Advanced{}
	}
	a := c.Advanced
	if a.TCPNodelay == nil {
		a.TCPNodelay = boolPtr(true)
	}
	positive(&a.TCPKeepalive, 15)
	positive(&a.TCPReadBuffer, 8<<20)
	positive(&a.TCPWriteBuffer, 8<<20)
	positive(&a.UDPReadBuffer, 4<<20)
	positive(&a.UDPWriteBuffer, 4<<20)
	positive(&a.WebsocketReadBuffer, 512<<10)
	positive(&a.WebsocketWriteBuffer, 512<<10)
	positive(&a.CleanupInterval, 60)
	positive(&a.SessionTimeout, 180)
	positive(&a.ConnectionTimeout, 600)
	positive(&a.StreamTimeout, 21600)
	positive(&a.StreamIdleTimeout, 600)
	positive(&a.MaxUDPFlows, 5000)
	positive(&a.UDPFlowTimeout, 600)
	if c.SMUX == nil {
		c.SMUX = &SMUX{}
	}
	s := c.SMUX
	keep, recv, stream, frame, mux := 15, 4<<20, 2<<20, 32768, 8
	switch c.Profile {
	case "aggressive":
		keep, recv, stream, frame, mux = 30, 8<<20, 4<<20, 65535, 16
	case "latency":
		keep, recv, stream, frame, mux = 5, 2<<20, 1<<20, 16384, 4
	case "cpu-efficient":
		keep, recv, stream, frame, mux = 60, 2<<20, 1<<20, 16384, 4
	}
	positive(&s.Keepalive, keep)
	positive(&s.MaxRecv, recv)
	positive(&s.MaxStream, stream)
	positive(&s.FrameSize, frame)
	positive(&s.Version, 2)
	positive(&s.MuxCon, mux)
	if c.KCP == nil {
		c.KCP = &KCP{Interval: 20, Resend: 2, Sndwnd: 512, Rcvwnd: 512, MTU: 1350, DataShard: 10, ParityShard: 3}
	}
	k := c.KCP
	positive(&k.Interval, 20)
	positive(&k.Sndwnd, 512)
	positive(&k.Rcvwnd, 512)
	positive(&k.MTU, 1350)
	if c.Encryption == nil {
		c.Encryption = &Encryption{}
	}
	if c.Encryption.Algorithm == "" {
		c.Encryption.Algorithm = "chacha20-poly1305"
	}
	if c.Compression == nil {
		c.Compression = &Compression{}
	}
	z := c.Compression
	if z.Algorithm == "" {
		z.Algorithm = "lz4"
	}
	positive(&z.MinSize, 1024)
	positive(&z.MaxSize, 65536)
	positive(&z.Level, 3)
	if c.Stealth == nil {
		c.Stealth = &Stealth{}
	}
	for i := range c.Paths {
		p := &c.Paths[i]
		if p.Transport == "" {
			p.Transport = c.Transport
		}
		positive(&p.ConnectionPool, c.ConnectionPool)
		positive(&p.RetryInterval, c.RetryInterval)
		positive(&p.DialTimeout, c.DialTimeout)
	}
}

var carriers = map[string]bool{"tcpmux": true, "tlsmux": true, "realitymux": true, "kcpmux": true, "wsmux": true, "wssmux": true, "rawsocket": true, "rawmux": true, "l3": true, "tcp": true, "tls": true, "kcp": true, "ws": true, "wss": true}

func validAddr(s string) bool {
	h, p, err := net.SplitHostPort(s)
	if err != nil || strings.ContainsAny(h, "\r\n\x00") {
		return false
	}
	port, e := strconv.Atoi(p)
	return e == nil && port > 0 && port <= 65535
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("missing configuration")
	}
	c.Defaults()
	if c.Mode != "server" && c.Mode != "client" {
		return errors.New("mode must be server or client")
	}
	if !carriers[c.Transport] {
		return errors.New("unknown transport")
	}
	switch c.Profile {
	case "balanced", "aggressive", "latency", "cpu-efficient":
	default:
		return errors.New("unknown profile")
	}
	if len(c.PSK) > 4096 || strings.ContainsAny(c.PSK, "\x00\r\n") {
		return errors.New("invalid local peer secret")
	}
	if c.PSK != "" && (strings.TrimSpace(c.PSK) == "" || strings.IndexFunc(strings.TrimSpace(c.PSK), unicode.IsSpace) >= 0) {
		return errors.New("local peer secret must be one nonempty token")
	}
	if c.HealthPort < 0 || c.HealthPort > 65535 {
		return errors.New("health_port must be 0..65535")
	}
	if c.RetryInterval < 1 || c.RetryInterval > 3600 || c.DialTimeout < 1 || c.DialTimeout > 3600 || c.Heartbeat < 1 || c.Heartbeat > 3600 {
		return errors.New("invalid retry, dial or heartbeat duration")
	}
	a := c.Advanced
	// The observed schema includes tuning knobs whose original scheduling logic
	// was not recovered. Reject changes rather than silently promise their effect.
	if a.AntiDpiDelayMs != 0 || a.StreamQueueSize != 0 || a.BufferPoolSize != 0 || a.LargeBufferPoolSize != 0 || a.UDPFramePoolSize != 0 || a.UDPDataSliceSize != 0 {
		return errors.New("custom anti-DPI, queue and allocator tuning is not reconstructed")
	}
	if a.CleanupInterval != 60 || a.SessionTimeout != 180 || a.ConnectionTimeout != 600 || a.StreamTimeout != 21600 || a.StreamIdleTimeout != 600 {
		return errors.New("custom reference cleanup/session/stream timeout policy is not reconstructed; use SMUX keepalive and UDP flow timeout")
	}
	if c.AggressivePool || c.Heartbeat != 5 {
		return errors.New("reference aggressive-pool policy and custom top-level heartbeat are not reconstructed")
	}
	validateReality := func(r *Reality) error {
		if r != nil && (r.PublicKey != "" || r.ShortId != "") {
			return errors.New("REALITY public_key/short_id authentication is not established; this carrier is browser-shaped TLS")
		}
		if r != nil {
			switch strings.ToLower(r.Fingerprint) {
			case "", "chrome", "firefox", "safari", "edge", "randomized":
			default:
				return errors.New("unsupported browser fingerprint")
			}
		}
		return nil
	}
	if err := validateReality(c.Reality); err != nil {
		return err
	}
	for _, size := range []int{a.TCPReadBuffer, a.TCPWriteBuffer, a.UDPReadBuffer, a.UDPWriteBuffer, a.WebsocketReadBuffer, a.WebsocketWriteBuffer} {
		if size < 1 || size > 64<<20 {
			return errors.New("socket buffer exceeds bounds")
		}
	}
	for _, duration := range []int{a.TCPKeepalive, a.CleanupInterval, a.SessionTimeout, a.ConnectionTimeout, a.StreamTimeout, a.StreamIdleTimeout, a.UDPFlowTimeout} {
		if duration < 1 || duration > 86400 {
			return errors.New("advanced duration exceeds bounds")
		}
	}
	if a.MaxConnections < 0 || a.MaxConnections > 65536 || a.MaxUDPFlows < 1 || a.MaxUDPFlows > 65536 || a.AntiDpiDelayMs < 0 || a.AntiDpiDelayMs > 10000 {
		return errors.New("advanced connection/flow/delay bounds exceeded")
	}
	if c.Transport != "l3" {
		if c.Mode == "server" && !c.Direct && !validAddr(c.Listen) {
			return errors.New("server needs listen host:port")
		}
		if c.Mode == "server" && c.Direct && !validAddr(c.Connect) {
			return errors.New("direct server needs connect host:port")
		}
		if c.Mode == "client" && c.Direct && !validAddr(c.Listen) {
			return errors.New("direct client needs listen host:port")
		}
		if c.Mode == "client" && !c.Direct && len(c.Paths) == 0 {
			return errors.New("client needs at least one path")
		}
	}
	if c.ConnectionPool < 1 || c.ConnectionPool > 256 || len(c.Paths) > 64 {
		return errors.New("connection pool or path count exceeds limits")
	}
	for _, p := range c.Paths {
		if p.AggressivePool {
			return errors.New("reference aggressive-pool policy is not reconstructed")
		}
		if err := validateReality(p.Reality); err != nil {
			return err
		}
		if !carriers[p.Transport] || p.Transport == "l3" || !validAddr(p.Addr) || p.ConnectionPool < 1 || p.ConnectionPool > 256 || p.DialTimeout < 1 || p.DialTimeout > 3600 || p.RetryInterval < 1 || p.RetryInterval > 3600 {
			return errors.New("invalid peer path")
		}
	}
	s := c.SMUX
	if s.Version < 1 || s.Version > 2 || s.MaxStream < 1024 || s.MaxRecv < s.MaxStream || s.MaxRecv > 256<<20 || s.FrameSize < 1024 || s.FrameSize > 65535 || s.MuxCon < 1 || s.MuxCon > 64 || s.Keepalive < 1 || s.Keepalive > 3600 {
		return errors.New("invalid smux bounds")
	}
	k := c.KCP
	if k.MTU < 256 || k.MTU > 1500 || k.Interval < 1 || k.Interval > 5000 || k.Sndwnd < 1 || k.Sndwnd > 1<<20 || k.Rcvwnd < 1 || k.Rcvwnd > 1<<20 || k.DataShard < 0 || k.ParityShard < 0 || k.DataShard+k.ParityShard > 255 || k.Nodelay < 0 || k.Nodelay > 1 || k.Nc < 0 || k.Nc > 1 || k.Resend < 0 || k.Resend > 10 {
		return errors.New("invalid KCP bounds")
	}
	z := c.Compression
	if z.MinSize < 1 || z.MaxSize < z.MinSize || z.MaxSize > 1<<20 {
		return errors.New("invalid compression sizes")
	}
	switch z.Algorithm {
	case "lz4", "zstd", "snappy":
	default:
		return errors.New("unknown compression algorithm")
	}
	switch c.Encryption.Algorithm {
	case "chacha", "chacha20-poly1305", "aes-gcm", "aes-256-gcm":
	default:
		return errors.New("unknown encryption algorithm")
	}
	if len(c.Encryption.Key) > 4096 || (c.Transport != "l3" && c.Encryption.Enabled && strings.TrimSpace(c.Encryption.Key) == "" && strings.TrimSpace(c.PSK) == "") {
		return errors.New("ordinary encryption needs a bounded local key or peer secret")
	}
	p := c.Stealth
	if p.PaddingMin < 0 || p.PaddingMax < p.PaddingMin || p.PaddingMax > 255 || p.JitterMinMs < 0 || p.JitterMaxMs < p.JitterMinMs || p.JitterMaxMs > 10000 {
		return errors.New("invalid padding or jitter bounds")
	}
	if c.CertFile != "" != (c.KeyFile != "") {
		return errors.New("cert_file and key_file must be supplied together")
	}
	if pp := c.ProxyProtocol; pp != nil && pp.Enabled {
		valid := func(s string) bool { return s == "" || s == "v1" || s == "v2" || s == "1" || s == "2" }
		if !valid(pp.Version) {
			return errors.New("PROXY version must be v1 or v2")
		}
		for port, version := range pp.Ports {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 || !valid(version) {
				return errors.New("invalid PROXY port/version")
			}
		}
	}
	if c.Tun != nil && c.Tun.Enabled {
		if c.Tun.HealthPort < 0 || c.Tun.HealthPort > 65535 {
			return errors.New("tun.health_port must be 0..65535")
		}
		if c.Tun.Name == "" {
			c.Tun.Name = "netrix0"
		}
		if len(c.Tun.Name) > 15 || strings.ContainsAny(c.Tun.Name, "/\r\n\x00 ") {
			return errors.New("invalid TUN interface name")
		}
		if _, _, e := net.ParseCIDR(c.Tun.Local); e != nil {
			return errors.New("tun.local needs IP/prefix")
		}
		positive(&c.Tun.MTU, 1400)
		positive(&c.Tun.Streams, 1)
		if c.Tun.MTU < 576 || c.Tun.MTU > 65535 || c.Tun.Streams < 1 || c.Tun.Streams > 64 {
			return errors.New("invalid TUN bounds")
		}
		for _, r := range c.Tun.Routes {
			if _, _, e := net.ParseCIDR(r); e != nil {
				return errors.New("invalid TUN route")
			}
		}
	}
	for _, m := range c.Maps {
		if (m.Type != "tcp" && m.Type != "udp") || !validAddr(m.Bind) || !validAddr(m.Target) {
			return errors.New("maps need tcp/udp type and bind/target host:port")
		}
	}
	_, err := c.Mappings()
	return err
}
