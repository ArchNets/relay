// Protocol verification by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"netrix.local/ir_spoof/internal/config"
)

// Expected hashes and PBKDF2 results were generated independently with Python's
// hashlib from the statically recovered exact context strings.
func TestReferenceScopeVectors(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	tests := []struct {
		carrier, algo, psk string
		encrypted          bool
		iterations         int
		sid                uint32
		key                string
	}{
		{"raw", "", "", false, 1000, 0xbe38eebe, ""},
		{"udp", "aes-128-gcm", "local-lab-secret", true, 1000, 0x7f1cf6df, "a5945ec9f70a46f34d9d9660610dc935"},
		{"icmp", "chacha20-poly1305", "b64:" + base64.StdEncoding.EncodeToString(secret), true, 4096, 0x79ae95eb, "e1727b62d22d1c3c3fcff0dceafd0496be81cb8897972dd1f2c139c8e96c48c5"},
	}
	for _, tt := range tests {
		s := Scope{Carrier: tt.carrier, LocalIP: "192.0.2.2", PeerIP: "192.0.2.10", LocalPort: 40002, PeerPort: 40001, ICMPType: 8, TUNLocal: "10.60.0.2/30", TUNRemote: "10.60.0.1/30", Encrypted: tt.encrypted, Algorithm: tt.algo, PSK: tt.psk, Iterations: tt.iterations}
		sid, err := s.SessionID()
		if err != nil || sid != tt.sid {
			t.Fatalf("SID %s: got %08x, %v", tt.carrier, sid, err)
		}
		key, _, err := s.DeriveKey(sid)
		if err != nil || hex.EncodeToString(key) != tt.key {
			t.Fatalf("KDF %s: got %x, %v", tt.carrier, key, err)
		}
		s.LocalIP, s.PeerIP = s.PeerIP, s.LocalIP
		s.LocalPort, s.PeerPort = s.PeerPort, s.LocalPort
		s.TUNLocal, s.TUNRemote = s.TUNRemote, s.TUNLocal
		if reverse, err := s.SessionID(); err != nil || reverse != sid {
			t.Fatal("peer direction changed SID", err)
		}
	}
}

func TestCipherPacketIndependentVector(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := NewCipher(key, "aes-256-gcm", bytes.NewReader([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 1}))
	if err != nil {
		t.Fatal(err)
	}
	e := Encoder{SessionID: 0x12345678, Instance: 0x3456, Cipher: c}
	frame, err := e.Encode([]byte{0x45, 0, 0}, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "4e4c33581234567800000027000134560000000000000001aabbccdd00000000000000014fe77537d67ebb49e74b8280013ba303a6b9fd"
	if hex.EncodeToString(frame) != want {
		t.Fatalf("packet mismatch: %x", frame)
	}
	d := Decoder{SessionID: e.SessionID, Cipher: c}
	if _, value, err := d.Decode(frame); err != nil || !bytes.Equal(value, []byte{0x45, 0, 0}) {
		t.Fatalf("decode: %x %v", value, err)
	}
	if _, _, err := d.Decode(frame); !errors.Is(err, ErrReplay) {
		t.Fatal("duplicate admitted", err)
	}
	frame[15] ^= 1
	if _, _, err := d.Decode(frame); !errors.Is(err, ErrAuthentication) {
		t.Fatal("AAD modification admitted", err)
	}
}

func TestCipherAlgorithmsAndHeartbeat(t *testing.T) {
	for _, algorithm := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"} {
		size := 32
		if algorithm == "aes-128-gcm" {
			size = 16
		}
		c, err := NewCipher(make([]byte, size), algorithm, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
		if err != nil {
			t.Fatal(err)
		}
		e := Encoder{SessionID: 123, Instance: 4, Cipher: c}
		d := Decoder{SessionID: 123, Cipher: c}
		frame, err := e.Encode(nil, FlagControl)
		if err != nil {
			t.Fatal(err)
		}
		h, payload, err := d.Decode(frame)
		if err != nil || len(payload) != 0 || h.Flags != FlagControl|FlagEncrypted || h.Sequence != 1 {
			t.Fatal("bad authenticated heartbeat", err)
		}
		if _, err := NewCipher(make([]byte, size), algorithm, bytes.NewReader(nil)); err == nil {
			t.Fatal("random failure ignored")
		}
	}
}

func TestFullRandomNonceAcrossPacketsAndInstances(t *testing.T) {
	// A deterministic entropy stream checks that every complete nonce is drawn,
	// including all eight bytes formerly occupied by the restarted counter.
	entropy := make([]byte, 36)
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}
	random := bytes.NewReader(entropy)
	key := make([]byte, 32)
	c, err := NewCipher(key, "aes-256-gcm", random)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		if i == 2 {
			c, err = NewCipher(key, "aes-256-gcm", random)
			if err != nil {
				t.Fatal(err)
			}
		}
		payload, err := c.Seal([]byte{0x45}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload[:12], entropy[i*12:(i+1)*12]) {
			t.Fatalf("nonce %d did not consume complete entropy: %x", i, payload[:12])
		}
		if seen[string(payload[:12])] {
			t.Fatal("repeated nonce across sender instances")
		}
		seen[string(payload[:12])] = true
		if plain, err := c.Open(payload, nil); err != nil || !bytes.Equal(plain, []byte{0x45}) {
			t.Fatal("nonce record decode", err)
		}
	}
	if _, err := c.Seal([]byte{1}, nil); err == nil {
		t.Fatal("runtime entropy failure ignored")
	}
	if _, err := c.Seal([]byte{1}, nil); err == nil {
		t.Fatal("failed cipher resumed")
	}
	c, err = NewCipher(key, "aes-256-gcm", bytes.NewReader(make([]byte, 12)))
	if err != nil {
		t.Fatal(err)
	}
	c.sends = 1 << 32
	if _, err := c.Seal([]byte{1}, nil); err == nil {
		t.Fatal("random nonce usage bound ignored")
	}
}

func TestFragmentReorderingAndBounds(t *testing.T) {
	e := Encoder{SessionID: 10, Instance: 20}
	payload := bytes.Repeat([]byte{0x45, 1, 2, 3, 4}, 300)
	frames, err := e.EncodePacket(payload, 256)
	if err != nil || len(frames) != 6 {
		t.Fatal("fragment generation", err)
	}
	d := Decoder{SessionID: 10}
	r := new(Reassembler)
	var output []byte
	for i := len(frames) - 1; i >= 0; i-- {
		h, piece, err := d.Decode(frames[i])
		if err != nil {
			t.Fatal(err)
		}
		output, err = r.Add(h, piece, time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(output, payload) {
		t.Fatal("reordered packet failed")
	}
	h, piece, _ := Inspect(frames[0], 10)
	if _, err := r.Add(h, piece, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(h, piece, time.Unix(1, 0)); err == nil {
		t.Fatal("duplicate piece admitted")
	}
	bad := append([]byte(nil), piece...)
	bad[4] = 0
	if _, err := r.Add(h, bad, time.Unix(1, 0)); err == nil {
		t.Fatal("one-fragment envelope admitted")
	}
}

func TestReplayWindowAndInstanceBounds(t *testing.T) {
	w := new(ReplayWindow)
	for _, n := range []uint64{3, 1, 2, 8192, 8194} {
		if !w.Accept(n) {
			t.Fatalf("fresh %d rejected", n)
		}
	}
	if w.Accept(1) || w.Accept(3) || w.Accept(8192) || w.Accept(0) {
		t.Fatal("replay/stale/zero accepted")
	}
	d := Decoder{SessionID: 1}
	var first []byte
	for i := 1; i <= 65; i++ {
		e := Encoder{SessionID: 1, Instance: uint16(i)}
		frame, _ := e.Encode([]byte{1}, 0)
		if i == 1 {
			first = frame
		}
		_, _, err := d.Decode(frame)
		if i <= 64 && err != nil || i == 65 && !errors.Is(err, ErrSession) {
			t.Fatalf("instance cap %d: %v", i, err)
		}
	}
	if _, _, err := d.Decode(first); !errors.Is(err, ErrReplay) {
		t.Fatal("old instance replay history reset")
	}
}

func TestMalformedRecords(t *testing.T) {
	e := Encoder{SessionID: 1, Instance: 1}
	frame, _ := e.Encode([]byte{1}, 0)
	for n := 0; n < len(frame); n++ {
		if _, _, err := Inspect(frame[:n], 1); err == nil {
			t.Fatalf("truncated length %d accepted", n)
		}
	}
	if _, _, err := Inspect(append(frame, 0), 1); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	frame[12], frame[13] = 0, 6
	if _, _, err := Inspect(frame, 1); err == nil {
		t.Fatal("contradictory flags accepted")
	}
	if _, _, err := Inspect(Probe(1), 1); err != nil {
		t.Fatal("reference control-only probe", err)
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	return w.Buffer.Write(p[:min(len(p), 3)])
}

func TestReferenceTCPOuterLength(t *testing.T) {
	e := Encoder{SessionID: 1, Instance: 1}
	frame, _ := e.Encode([]byte{0x45, 0, 0, 0}, 0)
	w := new(shortWriter)
	if err := WriteStreamRecord(w, frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes()[:4], []byte{0, 0, 0, 28}) {
		t.Fatalf("length prefix: %x", w.Bytes()[:4])
	}
	record, err := ReadStreamRecord(bytes.NewReader(w.Bytes()))
	if err != nil || !bytes.Equal(record, frame) {
		t.Fatalf("stream roundtrip: %v", err)
	}
	if _, err = ReadStreamRecord(bytes.NewReader(w.Bytes()[:9])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncation: %v", err)
	}
	if _, err = ReadStreamRecord(bytes.NewReader([]byte{255, 255, 255, 255})); err == nil {
		t.Fatal("unbounded stream length accepted")
	}
}

func basicConfig() *config.Config {
	return &config.Config{Mode: "server", Transport: "l3", PSK: "local-lab-secret", L3: &config.L3{Carrier: "udp", ListenIP: "192.0.2.1", DstIP: "192.0.2.2"}, Tun: &config.TUN{Enabled: true, Name: "nxtun0", Local: "10.60.0.1/30", Remote: "10.60.0.2/30", MTU: 1320}}
}

// Expected SID values and keys were checked against original-core captures in
// an isolated synthetic-address lab. The encrypted heartbeat is captured wire
// data, so a wrong SID/KDF context cannot pass by testing two matching rewrites.
func TestRuntimeScopeMatchesReferenceCapturedSIDsAndCiphertext(t *testing.T) {
	tests := []struct {
		carrier string
		sid     uint32
		key     string
		spoof   bool
	}{
		{"raw", 0x0ade2bb2, "87cf5d71176c8169098791685fa62f77105756285249f701ae4ce5b39c54bbba", false},
		{"udp", 0xbdd45a0e, "be64819fb102482527c43a51859fa79015e7ba7593cf1f9ee436ffc8c74f0b46", false},
		{"pcap", 0xbdd45a0e, "be64819fb102482527c43a51859fa79015e7ba7593cf1f9ee436ffc8c74f0b46", false},
		{"icmp", 0xe232e3cf, "e8ff3fdd8c9733d048cc7ac2731793e7c075b3e737732bc75b07930a79d64e11", false},
		{"tcp", 0x9577aaab, "52303865c70ee4486ae1b85b2385b732089ea6ecc48b30682c360b14c0005916", false},
		{"raw", 0x0dc0f91d, "5c32f462cb844995616d13e99e3fa235285a67bcd2e37182d5668887307d4e68", true},
	}
	for _, tt := range tests {
		c := basicConfig()
		c.PSK = "ir_spoof-isolated-fixture-v3"
		c.Tun.Local, c.Tun.Remote = "198.18.0.1/30", "198.18.0.2/30"
		c.L3.Carrier, c.L3.Interface, c.L3.ICMPType = tt.carrier, "lab0", 8
		if tt.spoof {
			c.L3.SpoofSrcIP, c.L3.SpoofDstIP = "192.0.2.101", "192.0.2.102"
		}
		s, err := loadSettings(c)
		if err != nil {
			t.Fatal(err)
		}
		if s.local != "198.18.0.1/30" || s.scope.TUNLocal != "198.18.0.1" || s.scope.TUNRemote != "198.18.0.2" {
			t.Fatal("device prefix or normalized wire scope changed incorrectly")
		}
		sid, err := s.scope.SessionID()
		if err != nil || sid != tt.sid {
			t.Fatalf("captured %s SID mismatch: %08x, %v", tt.carrier, sid, err)
		}
		key, algorithm, err := s.scope.DeriveKey(sid)
		if err != nil || hex.EncodeToString(key) != tt.key {
			t.Fatalf("captured %s KDF mismatch: %x, %v", tt.carrier, key, err)
		}
		c.Tun.Remote = "198.18.0.2"
		plainRemote, err := loadSettings(c)
		if err != nil {
			t.Fatal(err)
		}
		if plainSID, err := plainRemote.scope.SessionID(); err != nil || plainSID != sid {
			t.Fatal("remote prefix changed the wire SID")
		}
		if tt.carrier == "udp" {
			frame, err := hex.DecodeString("4e4c3358bdd45a0e000000240003670b0000000000000003b8c5b2f600000000000000035f2ccbb5c9fcb0c734345915052844bb")
			if err != nil {
				t.Fatal(err)
			}
			cipher, err := NewCipher(key, algorithm, nil)
			if err != nil {
				t.Fatal(err)
			}
			decoder := Decoder{SessionID: sid, Cipher: cipher}
			header, payload, err := decoder.Decode(frame)
			if err != nil || header.Sequence != 3 || header.Instance != 26379 || header.Flags != FlagEncrypted|FlagControl || len(payload) != 0 {
				t.Fatalf("original heartbeat authentication failed: %+v, %x, %v", header, payload, err)
			}
		}
	}
}

func TestConfigurationAndMappingDefaults(t *testing.T) {
	c := basicConfig()
	c.HealthPort = 8000
	c.Tun.HealthPort = 8001
	c.TCPPorts = []any{8080, "8081:81", "127.0.0.1:8082:82", "8083:127.0.0.1:83"}
	s, err := loadSettings(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.healthPort != 8000 {
		t.Fatal("top-level health port did not win")
	}
	want := []string{"10.60.0.2:8080", "10.60.0.2:81", "10.60.0.2:82", "127.0.0.1:83"}
	for i, row := range s.mappings {
		if row.Target != want[i] {
			t.Fatalf("mapping %d: %s", i, row.Target)
		}
	}
	c.Tun.Remote = "10.60.0.2"
	if err := Validate(c); err != nil {
		t.Fatalf("plain remote IP rejected: %v", err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	mutations := []func(*config.Config){
		func(c *config.Config) { c.L3.Carrier = "unknown" },
		func(c *config.Config) { c.L3.ListenIP = "example.invalid" },
		func(c *config.Config) { c.L3.FragmentSize = 128 },
		func(c *config.Config) { c.L3.SpoofSrcIP = "192.0.2.3" },
		func(c *config.Config) { c.L3.KDFIterations = MaximumIterations + 1 },
		func(c *config.Config) { value := true; c.L3.AllowIPFrag = &value },
		func(c *config.Config) { c.L3.PcapPollMs = 100 },
	}
	for i, mutate := range mutations {
		c := basicConfig()
		mutate(c)
		if err := Validate(c); err == nil {
			t.Fatalf("invalid config %d accepted", i)
		}
	}
}

func TestExtendedScopedOptions(t *testing.T) {
	c := basicConfig()
	value := true
	c.L3.Carrier = "raw"
	c.L3.AllowIPFrag = &value
	c.Tun.MTU = 3000
	if err := Validate(c); err != nil {
		t.Fatalf("raw IP fragments: %v", err)
	}
	c.Tun.MTU = 65535
	if err := Validate(c); err == nil {
		t.Fatal("oversize fragmented IPv4 record admitted")
	}
	c = basicConfig()
	c.L3.Carrier = "pcap"
	c.L3.Interface = "eth0"
	c.L3.PcapSnaplen = 4096
	c.L3.PcapPollMs = 100
	c.L3.PcapPromisc = &value
	c.L3.PcapFilter = "udp"
	s, err := loadSettings(c)
	if err != nil {
		t.Fatalf("capture settings without explicit MAC: %v", err)
	}
	if !s.packet.PcapPromisc || s.packet.PcapFilter != "udp" || !s.packet.AFPacket {
		t.Fatal("capture settings not passed through")
	}
	c = basicConfig()
	c.Tun.ForwardL2TP = true
	s, err = loadSettings(c)
	if err != nil || s.forward == nil {
		t.Fatalf("L2TP settings: %v", err)
	}
	c.Tun.L2TPDestIP = "example.invalid"
	if Validate(c) == nil {
		t.Fatal("hostname L2TP destination admitted")
	}
}
