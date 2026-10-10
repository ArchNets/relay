// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

const FragmentHeaderSize = 8

// EncodePacket uses the recovered eight-byte fragment prefix. Each fragment is
// an independently sequenced and authenticated NL3X record. FragmentSize denotes
// data bytes per fragment; it excludes both protocol prefixes and AEAD overhead.
func (e *Encoder) EncodePacket(payload []byte, fragmentSize int) ([][]byte, error) {
	if len(payload) == 0 || len(payload) > MaximumPayload {
		return nil, ErrFrame
	}
	if fragmentSize <= 0 || len(payload) <= fragmentSize {
		frame, err := e.Encode(payload, 0)
		if err != nil {
			return nil, err
		}
		return [][]byte{frame}, nil
	}
	count := (len(payload) + fragmentSize - 1) / fragmentSize
	if fragmentSize < 1 || fragmentSize > MaximumPayload-FragmentHeaderSize || count < 2 || count > 256 {
		return nil, ErrFrame
	}
	var id [4]byte
	for n := 0; n < 16; n++ {
		if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
			return nil, ErrFrame
		}
		if binary.BigEndian.Uint32(id[:]) != 0 {
			break
		}
	}
	if binary.BigEndian.Uint32(id[:]) == 0 {
		return nil, ErrFrame
	}
	frames := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		start := index * fragmentSize
		part := payload[start:min(start+fragmentSize, len(payload))]
		fragment := make([]byte, FragmentHeaderSize+len(part))
		copy(fragment, id[:])
		fragment[4] = byte(count - 1)
		fragment[5] = byte(index)
		binary.BigEndian.PutUint16(fragment[6:8], uint16(len(part)))
		copy(fragment[8:], part)
		frame, err := e.Encode(fragment, FlagFragment)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

type fragmentKey struct {
	instance uint16
	id       uint32
}
type fragmentSet struct {
	parts           [][]byte
	bytes, received int
	deadline        time.Time
}

// Reassembler enforces independent reconstruction bounds: 64 incomplete
// messages, 65535 bytes per message and five seconds to finish each message.
// Call only after packet authentication and replay admission have succeeded.
type Reassembler struct {
	mu   sync.Mutex
	sets map[fragmentKey]*fragmentSet
}

func (r *Reassembler) Add(h Header, payload []byte, now time.Time) ([]byte, error) {
	if h.Flags&FlagFragment == 0 {
		return payload, nil
	}
	if len(payload) < FragmentHeaderSize {
		return nil, ErrFrame
	}
	id := binary.BigEndian.Uint32(payload[:4])
	count, index := int(payload[4])+1, int(payload[5])
	length := int(binary.BigEndian.Uint16(payload[6:8]))
	if id == 0 || count < 2 || index >= count || length == 0 || length != len(payload)-FragmentHeaderSize {
		return nil, ErrFrame
	}
	key := fragmentKey{h.Instance, id}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sets == nil {
		r.sets = make(map[fragmentKey]*fragmentSet)
	}
	for k, set := range r.sets {
		if !now.Before(set.deadline) {
			delete(r.sets, k)
		}
	}
	set := r.sets[key]
	if set == nil {
		if len(r.sets) >= 64 {
			return nil, ErrFrame
		}
		set = &fragmentSet{parts: make([][]byte, count), deadline: now.Add(5 * time.Second)}
		r.sets[key] = set
	}
	if len(set.parts) != count || set.parts[index] != nil || set.bytes+length > MaximumPayload {
		delete(r.sets, key)
		return nil, ErrFrame
	}
	set.parts[index] = append([]byte(nil), payload[8:]...)
	set.bytes += length
	set.received++
	if set.received != count {
		return nil, nil
	}
	packet := make([]byte, 0, set.bytes)
	for _, part := range set.parts {
		packet = append(packet, part...)
	}
	delete(r.sets, key)
	return packet, nil
}
