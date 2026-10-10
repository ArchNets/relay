// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
// Scope hashing and PBKDF2 parameters recovered from the v3.0.1 Linux core.
package l3

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const DefaultIterations = 100000
const MaximumIterations = 10000000

// Scope describes the stable peer-pair fields used by the original SID and KDF.
// The on-wire raw IP protocol and scope protocol are both 58 in the reference.
// Local/peer fields can be reversed between peers without changing the scope.
// TUNLocal/TUNRemote are parsed IP address strings, without prefix lengths.
type Scope struct {
	Carrier                string
	LocalIP, PeerIP        string
	SpoofSrcIP, SpoofDstIP string
	LocalPort, PeerPort    int
	ICMPType, ICMPCode     int
	TUNLocal, TUNRemote    string
	Encrypted              bool
	Algorithm, PSK         string
	Iterations             int
}

func NormalizeAlgorithm(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "aes", "aes-gcm", "aes-256-gcm":
		return "aes-256-gcm", nil
	case "aes-128-gcm":
		return "aes-128-gcm", nil
	case "chacha", "chacha20", "chacha20-poly1305":
		return "chacha20-poly1305", nil
	default:
		return "", errors.New("l3: unsupported packet encryption algorithm")
	}
}

func DecodePSK(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("l3: encrypted packets require a local peer secret")
	}
	prefix := strings.ToLower(value)
	cut := 0
	if strings.HasPrefix(prefix, "b64:") {
		cut = 4
	}
	if strings.HasPrefix(prefix, "base64:") {
		cut = 7
	}
	if cut != 0 {
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[cut:]))
		if err != nil || len(data) == 0 {
			return nil, errors.New("l3: invalid base64 peer secret")
		}
		return data, nil
	}
	return []byte(value), nil
}

func canonicalIP(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	if ip, _, err := net.ParseCIDR(value); err == nil {
		return ip.String()
	}
	return ""
}

func ordered(a, b string) (string, string) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a > b {
		a, b = b, a
	}
	return a, b
}

func (s Scope) parts() (carrier, first, second, wire, tunFirst, tunSecond, algorithm, token string, err error) {
	carrier = strings.ToLower(strings.TrimSpace(s.Carrier))
	if carrier == "" {
		carrier = "raw"
	}
	switch carrier {
	case "raw":
		wire = "raw"
	case "tcp", "udp", "pcap":
		if s.LocalPort < 0 || s.LocalPort > 65535 || s.PeerPort < 0 || s.PeerPort > 65535 {
			err = errors.New("l3: invalid packet port")
			return
		}
		if carrier == "pcap" {
			carrier = "udp"
		}
		wire = fmt.Sprintf("%s=%d|%d", carrier, min(s.LocalPort, s.PeerPort), max(s.LocalPort, s.PeerPort))
	case "icmp":
		if s.ICMPType < 0 || s.ICMPType > 255 || s.ICMPCode < 0 || s.ICMPCode > 255 {
			err = errors.New("l3: invalid ICMP type or code")
			return
		}
		wire = fmt.Sprintf("icmp=%d/%d", s.ICMPType, s.ICMPCode)
	default:
		err = errors.New("l3: unsupported packet carrier")
		return
	}
	first, second = canonicalIP(s.SpoofSrcIP), canonicalIP(s.SpoofDstIP)
	if first == "" || second == "" {
		first, second = canonicalIP(s.LocalIP), canonicalIP(s.PeerIP)
	}
	first, second = ordered(first, second)
	tunFirst, tunSecond = ordered(s.TUNLocal, s.TUNRemote)
	algorithm, token = "none", "none"
	if s.Encrypted {
		algorithm, err = NormalizeAlgorithm(s.Algorithm)
		if err != nil {
			return
		}
		var secret []byte
		secret, err = DecodePSK(s.PSK)
		if err != nil {
			return
		}
		hash := sha256.Sum256(secret)
		token = hex.EncodeToString(hash[:8])
	}
	return
}

// SessionID returns the original stable NL3X SID. It makes no network requests.
func (s Scope) SessionID() (uint32, error) {
	carrier, a, b, wire, ta, tb, algo, token, err := s.parts()
	if err != nil {
		return 0, err
	}
	fingerprint := fmt.Sprintf("nl3|transport=l3|carrier=%s|proto=58|ep=%s|%s|wire=%s|tun=%s|%s|enc=%t|algo=%s|psk=%s", carrier, a, b, wire, ta, tb, s.Encrypted, algo, token)
	hash := sha256.Sum256([]byte(fingerprint))
	sid := binary.BigEndian.Uint32(hash[:4])
	if sid == 0 {
		sid = 0x13579bdf
	}
	return sid, nil
}

// DeriveKey uses the exact recovered context salt and PBKDF2-HMAC-SHA256.
// The local work cap rejects excessive KDF values before allocating resources.
func (s Scope) DeriveKey(sid uint32) ([]byte, string, error) {
	if !s.Encrypted {
		return nil, "none", nil
	}
	carrier, a, b, wire, ta, tb, algo, _, err := s.parts()
	if err != nil {
		return nil, "", err
	}
	secret, err := DecodePSK(s.PSK)
	if err != nil {
		return nil, "", err
	}
	iterations := s.Iterations
	if iterations <= 0 {
		iterations = DefaultIterations
	}
	if iterations > MaximumIterations {
		return nil, "", errors.New("l3: KDF work limit exceeded")
	}
	context := fmt.Sprintf("netrix-l3-kdf-v4|sid=%08x|transport=l3|carrier=%s|proto=58|ep=%s|%s|wire=%s|tun=%s|%s|enc=%t|algo=%s", sid, carrier, a, b, wire, ta, tb, s.Encrypted, algo)
	salt := sha256.Sum256([]byte(context))
	size := 32
	if algo == "aes-128-gcm" {
		size = 16
	}
	return pbkdf2.Key(secret, salt[:], iterations, size, sha256.New), algo, nil
}
