// Independent Linux reconstruction by t.me/ir_spoof.
// Schema recovered from v3.0.1 runtime types; no upstream source was supplied.
package config

type RawSocket struct {
	Interface   string   `yaml:"interface,omitempty" json:"interface,omitempty"`
	LocalIP     string   `yaml:"local_ip,omitempty" json:"local_ip,omitempty"`
	PeerIP      string   `yaml:"peer_ip,omitempty" json:"peer_ip,omitempty"`
	RouterMac   string   `yaml:"router_mac,omitempty" json:"router_mac,omitempty"`
	MTU         int      `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	SndWnd      int      `yaml:"snd_wnd,omitempty" json:"snd_wnd,omitempty"`
	RcvWnd      int      `yaml:"rcv_wnd,omitempty" json:"rcv_wnd,omitempty"`
	DataShard   int      `yaml:"data_shard,omitempty" json:"data_shard,omitempty"`
	ParityShard int      `yaml:"parity_shard,omitempty" json:"parity_shard,omitempty"`
	SockBuf     int      `yaml:"sock_buf,omitempty" json:"sock_buf,omitempty"`
	LocalFlags  []string `yaml:"local_flags,omitempty" json:"local_flags,omitempty"`
	RemoteFlags []string `yaml:"remote_flags,omitempty" json:"remote_flags,omitempty"`
}

type Path struct {
	Transport      string     `yaml:"transport" json:"transport"`
	Addr           string     `yaml:"addr" json:"addr"`
	EdgeIP         string     `yaml:"edge_ip,omitempty" json:"edge_ip,omitempty"`
	ConnectionPool int        `yaml:"connection_pool" json:"connection_pool"`
	AggressivePool bool       `yaml:"aggressive_pool" json:"aggressive_pool"`
	RetryInterval  int        `yaml:"retry_interval" json:"retry_interval"`
	DialTimeout    int        `yaml:"dial_timeout" json:"dial_timeout"`
	Reality        *Reality   `yaml:"reality,omitempty" json:"reality,omitempty"`
	Rawsocket      *RawSocket `yaml:"rawsocket,omitempty" json:"rawsocket,omitempty"`
}

type TUN struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	Local       string   `yaml:"local" json:"local"`
	Remote      string   `yaml:"remote,omitempty" json:"remote,omitempty"`
	MTU         int      `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	Streams     int      `yaml:"streams,omitempty" json:"streams,omitempty"`
	HealthPort  int      `yaml:"health_port,omitempty" json:"health_port,omitempty"`
	Routes      []string `yaml:"routes,omitempty" json:"routes,omitempty"`
	ForwardL2TP bool     `yaml:"forward_l2tp,omitempty" json:"forward_l2tp,omitempty"`
	L2TPPorts   []int    `yaml:"l2tp_ports,omitempty" json:"l2tp_ports,omitempty"`
	L2TPDestIP  string   `yaml:"l2tp_dest_ip,omitempty" json:"l2tp_dest_ip,omitempty"`
}

type L3 struct {
	Profile           string `yaml:"profile,omitempty" json:"profile,omitempty"`
	ChannelSize       int    `yaml:"channel_size,omitempty" json:"channel_size,omitempty"`
	BatchSize         int    `yaml:"batch_size,omitempty" json:"batch_size,omitempty"`
	Carrier           string `yaml:"carrier,omitempty" json:"carrier,omitempty"`
	ICMPType          int    `yaml:"icmp_type,omitempty" json:"icmp_type,omitempty"`
	ICMPCode          int    `yaml:"icmp_code,omitempty" json:"icmp_code,omitempty"`
	ListenIP          string `yaml:"listen_ip,omitempty" json:"listen_ip,omitempty"`
	ListenPort        int    `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	DstIP             string `yaml:"dst_ip,omitempty" json:"dst_ip,omitempty"`
	DstPort           int    `yaml:"dst_port,omitempty" json:"dst_port,omitempty"`
	Interface         string `yaml:"interface,omitempty" json:"interface,omitempty"`
	HeartbeatInterval int    `yaml:"heartbeat_interval,omitempty" json:"heartbeat_interval,omitempty"`
	HeartbeatTimeout  int    `yaml:"heartbeat_timeout,omitempty" json:"heartbeat_timeout,omitempty"`
	EnableEncryption  *bool  `yaml:"enable_encryption,omitempty" json:"enable_encryption,omitempty"`
	Algorithm         string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
	PSK               string `yaml:"psk,omitempty" json:"psk,omitempty"`
	KDFIterations     int    `yaml:"kdf_iterations,omitempty" json:"kdf_iterations,omitempty"`
	SoSndbuf          int    `yaml:"so_sndbuf,omitempty" json:"so_sndbuf,omitempty"`
	SoRcvbuf          int    `yaml:"so_rcvbuf,omitempty" json:"so_rcvbuf,omitempty"`
	FragmentSize      int    `yaml:"fragment_size,omitempty" json:"fragment_size,omitempty"`
	AllowIPFrag       *bool  `yaml:"allow_ip_frag,omitempty" json:"allow_ip_frag,omitempty"`
	SpoofSrcIP        string `yaml:"spoof_src_ip,omitempty" json:"spoof_src_ip,omitempty"`
	SpoofDstIP        string `yaml:"spoof_dst_ip,omitempty" json:"spoof_dst_ip,omitempty"`
	AFPacketTX        *bool  `yaml:"af_packet_tx,omitempty" json:"af_packet_tx,omitempty"`
	PcapFilter        string `yaml:"pcap_filter,omitempty" json:"pcap_filter,omitempty"`
	PcapSnaplen       int    `yaml:"pcap_snaplen,omitempty" json:"pcap_snaplen,omitempty"`
	PcapPromisc       *bool  `yaml:"pcap_promisc,omitempty" json:"pcap_promisc,omitempty"`
	PcapPollMs        int    `yaml:"pcap_poll_ms,omitempty" json:"pcap_poll_ms,omitempty"`
}

type KCP struct {
	Nodelay     int `yaml:"nodelay" json:"nodelay"`
	Interval    int `yaml:"interval" json:"interval"`
	Resend      int `yaml:"resend" json:"resend"`
	Nc          int `yaml:"nc" json:"nc"`
	Sndwnd      int `yaml:"sndwnd" json:"sndwnd"`
	Rcvwnd      int `yaml:"rcvwnd" json:"rcvwnd"`
	MTU         int `yaml:"mtu" json:"mtu"`
	DataShard   int `yaml:"data_shard,omitempty" json:"data_shard,omitempty"`
	ParityShard int `yaml:"parity_shard,omitempty" json:"parity_shard,omitempty"`
}

type Reality struct {
	SNI         string `yaml:"sni,omitempty" json:"sni,omitempty"`
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	ShortId     string `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	PublicKey   string `yaml:"public_key,omitempty" json:"public_key,omitempty"`
}

type Config struct {
	Mode           string         `yaml:"mode" json:"mode"`
	PSK            string         `yaml:"psk" json:"psk"`
	Profile        string         `yaml:"profile,omitempty" json:"profile,omitempty"`
	Direct         bool           `yaml:"direct,omitempty" json:"direct,omitempty"`
	Listen         string         `yaml:"listen,omitempty" json:"listen,omitempty"`
	Connect        string         `yaml:"connect,omitempty" json:"connect,omitempty"`
	EdgeIP         string         `yaml:"edge_ip,omitempty" json:"edge_ip,omitempty"`
	ConnectionPool int            `yaml:"connection_pool,omitempty" json:"connection_pool,omitempty"`
	RetryInterval  int            `yaml:"retry_interval,omitempty" json:"retry_interval,omitempty"`
	DialTimeout    int            `yaml:"dial_timeout,omitempty" json:"dial_timeout,omitempty"`
	AggressivePool bool           `yaml:"aggressive_pool,omitempty" json:"aggressive_pool,omitempty"`
	Transport      string         `yaml:"transport,omitempty" json:"transport,omitempty"`
	Reality        *Reality       `yaml:"reality,omitempty" json:"reality,omitempty"`
	Rawsocket      *RawSocket     `yaml:"rawsocket,omitempty" json:"rawsocket,omitempty"`
	L3             *L3            `yaml:"l3,omitempty" json:"l3,omitempty"`
	Maps           []Mapping      `yaml:"maps,omitempty" json:"maps,omitempty"`
	TCPPorts       []any          `yaml:"tcp_ports,omitempty" json:"tcp_ports,omitempty"`
	UDPPorts       []any          `yaml:"udp_ports,omitempty" json:"udp_ports,omitempty"`
	Paths          []Path         `yaml:"paths,omitempty" json:"paths,omitempty"`
	SMUX           *SMUX          `yaml:"smux,omitempty" json:"smux,omitempty"`
	KCP            *KCP           `yaml:"kcp,omitempty" json:"kcp,omitempty"`
	Advanced       *Advanced      `yaml:"advanced,omitempty" json:"advanced,omitempty"`
	Encryption     *Encryption    `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	Stealth        *Stealth       `yaml:"stealth,omitempty" json:"stealth,omitempty"`
	Compression    *Compression   `yaml:"compression,omitempty" json:"compression,omitempty"`
	Heartbeat      int            `yaml:"heartbeat,omitempty" json:"heartbeat,omitempty"`
	Verbose        *bool          `yaml:"verbose,omitempty" json:"verbose,omitempty"`
	HealthPort     int            `yaml:"health_port,omitempty" json:"health_port,omitempty"`
	CertFile       string         `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile        string         `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	CAFile         string         `yaml:"ca_file,omitempty" json:"ca_file,omitempty"` // Independent local trust extension.
	Tun            *TUN           `yaml:"tun,omitempty" json:"tun,omitempty"`
	ProxyProtocol  *ProxyProtocol `yaml:"proxy_protocol,omitempty" json:"proxy_protocol,omitempty"`
}

type Advanced struct {
	TCPNodelay            *bool `yaml:"tcp_nodelay,omitempty" json:"tcp_nodelay,omitempty"`
	TCPKeepalive          int   `yaml:"tcp_keepalive,omitempty" json:"tcp_keepalive,omitempty"`
	TCPReadBuffer         int   `yaml:"tcp_read_buffer,omitempty" json:"tcp_read_buffer,omitempty"`
	TCPWriteBuffer        int   `yaml:"tcp_write_buffer,omitempty" json:"tcp_write_buffer,omitempty"`
	UDPReadBuffer         int   `yaml:"udp_read_buffer,omitempty" json:"udp_read_buffer,omitempty"`
	UDPWriteBuffer        int   `yaml:"udp_write_buffer,omitempty" json:"udp_write_buffer,omitempty"`
	WebsocketReadBuffer   int   `yaml:"websocket_read_buffer,omitempty" json:"websocket_read_buffer,omitempty"`
	WebsocketWriteBuffer  int   `yaml:"websocket_write_buffer,omitempty" json:"websocket_write_buffer,omitempty"`
	WebsocketCompression  *bool `yaml:"websocket_compression,omitempty" json:"websocket_compression,omitempty"`
	CleanupInterval       int   `yaml:"cleanup_interval,omitempty" json:"cleanup_interval,omitempty"`
	SessionTimeout        int   `yaml:"session_timeout,omitempty" json:"session_timeout,omitempty"`
	ConnectionTimeout     int   `yaml:"connection_timeout,omitempty" json:"connection_timeout,omitempty"`
	StreamTimeout         int   `yaml:"stream_timeout,omitempty" json:"stream_timeout,omitempty"`
	StreamIdleTimeout     int   `yaml:"stream_idle_timeout,omitempty" json:"stream_idle_timeout,omitempty"`
	MaxConnections        int   `yaml:"max_connections,omitempty" json:"max_connections,omitempty"`
	StreamQueueSize       int   `yaml:"stream_queue_size,omitempty" json:"stream_queue_size,omitempty"`
	MaxUDPFlows           int   `yaml:"max_udp_flows,omitempty" json:"max_udp_flows,omitempty"`
	UDPFlowTimeout        int   `yaml:"udp_flow_timeout,omitempty" json:"udp_flow_timeout,omitempty"`
	BufferPoolSize        int   `yaml:"buffer_pool_size,omitempty" json:"buffer_pool_size,omitempty"`
	LargeBufferPoolSize   int   `yaml:"large_buffer_pool_size,omitempty" json:"large_buffer_pool_size,omitempty"`
	UDPFramePoolSize      int   `yaml:"udp_frame_pool_size,omitempty" json:"udp_frame_pool_size,omitempty"`
	UDPDataSliceSize      int   `yaml:"udp_data_slice_size,omitempty" json:"udp_data_slice_size,omitempty"`
	AntiDpiDelayMs        int   `yaml:"anti_dpi_delay_ms,omitempty" json:"anti_dpi_delay_ms,omitempty"`
	TLSInsecureSkipVerify *bool `yaml:"tls_insecure_skip_verify,omitempty" json:"tls_insecure_skip_verify,omitempty"`
}

type Stealth struct {
	PaddingEnabled bool `yaml:"padding_enabled,omitempty" json:"padding_enabled,omitempty"`
	PaddingMin     int  `yaml:"padding_min,omitempty" json:"padding_min,omitempty"`
	PaddingMax     int  `yaml:"padding_max,omitempty" json:"padding_max,omitempty"`
	JitterEnabled  bool `yaml:"jitter_enabled,omitempty" json:"jitter_enabled,omitempty"`
	JitterMinMs    int  `yaml:"jitter_min_ms,omitempty" json:"jitter_min_ms,omitempty"`
	JitterMaxMs    int  `yaml:"jitter_max_ms,omitempty" json:"jitter_max_ms,omitempty"`
}

type Encryption struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Key       string `yaml:"key,omitempty" json:"key,omitempty"`
	Algorithm string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
}

type ProxyProtocol struct {
	Enabled  bool              `yaml:"enabled" json:"enabled"`
	Version  string            `yaml:"version,omitempty" json:"version,omitempty"`
	Ports    map[string]string `yaml:"ports,omitempty" json:"ports,omitempty"`
	PortList []any             `yaml:"port_list,omitempty" json:"port_list,omitempty"`
}

type Mapping struct {
	Type   string `yaml:"type" json:"type"`
	Bind   string `yaml:"bind" json:"bind"`
	Target string `yaml:"target" json:"target"`
}

type Compression struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Algorithm string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
	Level     int    `yaml:"level,omitempty" json:"level,omitempty"`
	MinSize   int    `yaml:"min_size,omitempty" json:"min_size,omitempty"`
	MaxSize   int    `yaml:"max_size,omitempty" json:"max_size,omitempty"`
}

type SMUX struct {
	Keepalive int `yaml:"keepalive" json:"keepalive"`
	MaxRecv   int `yaml:"max_recv" json:"max_recv"`
	MaxStream int `yaml:"max_stream" json:"max_stream"`
	FrameSize int `yaml:"frame_size,omitempty" json:"frame_size,omitempty"`
	Version   int `yaml:"version,omitempty" json:"version,omitempty"`
	MuxCon    int `yaml:"mux_con,omitempty" json:"mux_con,omitempty"`
}
