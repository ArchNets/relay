// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
)

const (
	HeaderSize            = 24
	MaximumPayload        = 65535
	FlagEncrypted  uint16 = 1
	FlagControl    uint16 = 2
	FlagFragment   uint16 = 4
)

var (
	ErrFrame          = errors.New("l3: malformed or unsupported NL3X record")
	ErrAuthentication = errors.New("l3: packet authentication failed")
	ErrReplay         = errors.New("l3: replayed or stale packet")
	ErrSession        = errors.New("l3: packet belongs to another session")
)

type Header struct {
	SessionID uint32
	Flags     uint16
	Instance  uint16
	Sequence  uint64
}

// Inspect validates the reference NL3X fixed prefix. BodyLength includes the
// sequence bytes; therefore totalLength=16+bodyLength. A control-only probe may
// declare zero bodyLength and carry up to the 24-byte prefix without payload.
func Inspect(frame []byte, sid uint32) (Header, []byte, error) {
	var h Header
	if len(frame) < 16 || string(frame[:4]) != "NL3X" {
		return h, nil, ErrFrame
	}
	h.SessionID = binary.BigEndian.Uint32(frame[4:8])
	h.Flags = binary.BigEndian.Uint16(frame[12:14])
	h.Instance = binary.BigEndian.Uint16(frame[14:16])
	if h.SessionID != sid {
		return h, nil, ErrSession
	}
	if h.Instance == 0 || h.Flags&^uint16(7) != 0 || h.Flags&(FlagControl|FlagFragment) == FlagControl|FlagFragment {
		return h, nil, ErrFrame
	}
	body := uint64(binary.BigEndian.Uint32(frame[8:12]))
	if body == 0 && h.Flags&FlagControl != 0 {
		if h.Flags&FlagEncrypted != 0 || len(frame) > HeaderSize {
			return h, nil, ErrFrame
		}
		return h, nil, nil
	}
	if body < 8 || body > MaximumPayload+8+64 || body+16 > uint64(len(frame)) {
		return h, nil, ErrFrame
	}
	// Unlike the legacy parser, reject ambiguous trailing bytes on a datagram.
	if body+16 != uint64(len(frame)) {
		return h, nil, ErrFrame
	}
	h.Sequence = binary.BigEndian.Uint64(frame[16:24])
	if h.Sequence == 0 {
		return h, nil, ErrReplay
	}
	return h, frame[24:], nil
}

type Encoder struct {
	SessionID uint32
	Instance  uint16
	Cipher    *Cipher
	mu        sync.Mutex
	sequence  uint64
}

func NewEncoder(sid uint32, crypto *Cipher, random io.Reader) (*Encoder, error) {
	if random == nil {
		random = rand.Reader
	}
	var tag [2]byte
	for n := 0; n < 16; n++ {
		if _, err := io.ReadFull(random, tag[:]); err != nil {
			return nil, errors.New("l3: instance randomness unavailable")
		}
		if instance := binary.BigEndian.Uint16(tag[:]); instance != 0 {
			return &Encoder{SessionID: sid, Instance: instance, Cipher: crypto}, nil
		}
	}
	return nil, errors.New("l3: unable to generate nonzero instance")
}

func (e *Encoder) Encode(payload []byte, flags uint16) ([]byte, error) {
	if len(payload) > MaximumPayload || e.Instance == 0 || flags&^uint16(6) != 0 || flags&6 == 6 {
		return nil, ErrFrame
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sequence == math.MaxUint64 {
		return nil, errors.New("l3: record sequence exhausted")
	}
	e.sequence++
	bodySize := 8 + len(payload)
	if e.Cipher != nil {
		flags |= FlagEncrypted
		bodySize += e.Cipher.Overhead()
	}
	frame := make([]byte, HeaderSize)
	copy(frame, "NL3X")
	binary.BigEndian.PutUint32(frame[4:8], e.SessionID)
	binary.BigEndian.PutUint32(frame[8:12], uint32(bodySize))
	binary.BigEndian.PutUint16(frame[12:14], flags)
	binary.BigEndian.PutUint16(frame[14:16], e.Instance)
	binary.BigEndian.PutUint64(frame[16:24], e.sequence)
	if e.Cipher != nil {
		sealed, err := e.Cipher.Seal(payload, frame)
		if err != nil {
			return nil, err
		}
		return append(frame, sealed...), nil
	}
	return append(frame, payload...), nil
}

// Probe generates the observed unencrypted control-only record, with tag1 and
// zero bodyLength. It is not an authenticated keepalive for encrypted sessions.
func Probe(sid uint32) []byte {
	frame := make([]byte, HeaderSize)
	copy(frame, "NL3X")
	binary.BigEndian.PutUint32(frame[4:8], sid)
	binary.BigEndian.PutUint16(frame[12:14], FlagControl)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	return frame
}

// Decoder authenticates before updating an independent per-instance replay
// window. This reconstruction bounds one process to 64 sending-instance tags
// without evicting replay history. Exhaustion requires restarting the session;
// it never resets old history to accept an already authenticated packet twice.
type Decoder struct {
	SessionID uint32
	Cipher    *Cipher
	mu        sync.Mutex
	windows   map[uint16]*ReplayWindow
}

func (d *Decoder) Decode(frame []byte) (Header, []byte, error) {
	h, payload, err := Inspect(frame, d.SessionID)
	if err != nil {
		return h, nil, err
	}
	if h.Sequence == 0 {
		return h, nil, nil
	}
	if d.Cipher != nil {
		if h.Flags&FlagEncrypted == 0 {
			return h, nil, ErrAuthentication
		}
		payload, err = d.Cipher.Open(payload, frame[:HeaderSize])
		if err != nil {
			return h, nil, err
		}
	} else if h.Flags&FlagEncrypted != 0 {
		return h, nil, ErrAuthentication
	}
	if len(payload) > MaximumPayload {
		return h, nil, ErrFrame
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.windows == nil {
		d.windows = make(map[uint16]*ReplayWindow)
	}
	window := d.windows[h.Instance]
	if window == nil {
		if len(d.windows) >= 64 {
			return h, nil, ErrSession
		}
		window = new(ReplayWindow)
		d.windows[h.Instance] = window
	}
	if !window.Accept(h.Sequence) {
		return h, nil, ErrReplay
	}
	return h, payload, nil
}
