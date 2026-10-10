// Bounded IPv4 fragment handling by ir_spoof; https://t.me/ir_spoof.
package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"time"
)

var ErrFragmentPending = errors.New("packet: incomplete IPv4 fragment set")

const (
	maxFragmentFlows = 32
	maxFragmentParts = 128
	maxFragmentBytes = 1 << 20
	fragmentLifetime = 5 * time.Second
)

type fragmentKey struct {
	src, dst [4]byte
	protocol uint8
	id       uint16
}
type fragmentPart struct {
	offset int
	data   []byte
}
type fragmentSet struct {
	created    time.Time
	header     []byte
	parts      []fragmentPart
	end, bytes int
}

// Reassembler admits only the codec's configured wire peer. It bounds memory,
// lifetime and fragment counts, rejects conflicting overlaps, and verifies the
// completed transport through Codec.DecodePeer before exposing any payload.
// It is caller-owned and must be serialized (socketConn's read mutex does this).
type Reassembler struct {
	codec *Codec
	sets  map[fragmentKey]*fragmentSet
	bytes int
}

func NewReassembler(codec *Codec) *Reassembler {
	return &Reassembler{codec: codec, sets: make(map[fragmentKey]*fragmentSet)}
}

func (r *Reassembler) forget(key fragmentKey) {
	if set, ok := r.sets[key]; ok {
		r.bytes -= set.bytes
		delete(r.sets, key)
	}
}

// Assemble returns a complete IPv4 packet or ErrFragmentPending. Complete
// packets alias input; reconstructed packets own their storage. No address or
// packet data is logged. now is supplied so expiration tests need no sleeps.
func (r *Reassembler) Assemble(frame []byte, now time.Time) ([]byte, error) {
	if r == nil || r.codec == nil || len(frame) < 20 || frame[0]>>4 != 4 {
		return nil, ErrPacket
	}
	header := int(frame[0]&15) * 4
	length := int(binary.BigEndian.Uint16(frame[2:4]))
	if header < 20 || header > 60 || header > len(frame) || length < header || length > len(frame) || Checksum(frame[:header]) != 0 || !validIPOptions(frame[20:header]) {
		return nil, ErrPacket
	}
	if frame[9] != r.codec.protocol || !bytes.Equal(frame[12:16], r.codec.receiveSrc[:]) || !bytes.Equal(frame[16:20], r.codec.receiveDst[:]) {
		return nil, ErrAdmission
	}
	flags := binary.BigEndian.Uint16(frame[6:8])
	if flags&0x8000 != 0 || flags&0x4000 != 0 && flags&0x3fff != 0 {
		return nil, ErrPacket
	}
	if flags&0x3fff == 0 {
		if _, err := r.codec.Decode(frame[:length]); err != nil {
			return nil, err
		}
		return frame[:length], nil
	}
	if !r.codec.options.AllowIPFragments {
		return nil, ErrPacket
	}
	for key, set := range r.sets {
		if now.Sub(set.created) >= fragmentLifetime {
			r.forget(key)
		}
	}
	var key fragmentKey
	copy(key.src[:], frame[12:16])
	copy(key.dst[:], frame[16:20])
	key.protocol = frame[9]
	key.id = binary.BigEndian.Uint16(frame[4:6])
	offset := int(flags&0x1fff) * 8
	data := frame[header:length]
	end := offset + len(data)
	more := flags&0x2000 != 0
	if len(data) == 0 || more && len(data)%8 != 0 || end > 65535-header {
		r.forget(key)
		return nil, ErrPacket
	}
	set := r.sets[key]
	if set == nil {
		if len(r.sets) >= maxFragmentFlows {
			return nil, ErrPacket
		}
		set = &fragmentSet{created: now, end: -1}
		r.sets[key] = set
	}
	if len(set.header) > 0 && (len(set.header) != header || !bytes.Equal(set.header[20:], frame[20:header])) {
		r.forget(key)
		return nil, ErrPacket
	}
	if !more {
		if set.end >= 0 && set.end != end {
			r.forget(key)
			return nil, ErrPacket
		}
		set.end = end
	}
	if set.end >= 0 && end > set.end {
		r.forget(key)
		return nil, ErrPacket
	}
	for _, part := range set.parts {
		partEnd := part.offset + len(part.data)
		if offset == part.offset && len(data) == len(part.data) && bytes.Equal(data, part.data) {
			return nil, ErrFragmentPending
		}
		if offset < partEnd && end > part.offset {
			r.forget(key)
			return nil, ErrPacket
		}
		if !more && partEnd > end {
			r.forget(key)
			return nil, ErrPacket
		}
	}
	if len(set.parts) >= maxFragmentParts || r.bytes+len(data) > maxFragmentBytes {
		r.forget(key)
		return nil, ErrPacket
	}
	if offset == 0 {
		set.header = append([]byte(nil), frame[:header]...)
	}
	set.parts = append(set.parts, fragmentPart{offset: offset, data: append([]byte(nil), data...)})
	set.bytes += len(data)
	r.bytes += len(data)
	if set.end < 0 || len(set.header) == 0 || set.bytes != set.end {
		return nil, ErrFragmentPending
	}
	sort.Slice(set.parts, func(i, j int) bool { return set.parts[i].offset < set.parts[j].offset })
	cursor := 0
	for _, part := range set.parts {
		if part.offset != cursor {
			return nil, ErrFragmentPending
		}
		cursor += len(part.data)
	}
	if cursor != set.end || len(set.header)+cursor > 65535 {
		r.forget(key)
		return nil, ErrPacket
	}
	complete := make([]byte, len(set.header)+cursor)
	copy(complete, set.header)
	for _, part := range set.parts {
		copy(complete[len(set.header)+part.offset:], part.data)
	}
	binary.BigEndian.PutUint16(complete[2:4], uint16(len(complete)))
	binary.BigEndian.PutUint16(complete[6:8], 0)
	complete[10], complete[11] = 0, 0
	binary.BigEndian.PutUint16(complete[10:12], Checksum(complete[:len(set.header)]))
	r.forget(key)
	if _, err := r.codec.Decode(complete); err != nil {
		return nil, err
	}
	return complete, nil
}

// FragmentIPv4 splits a complete, DF-clear IPv4 datagram into independently
// checksummed packets at the supplied total-IP MTU. Fragments use one packet ID
// and eight-byte offsets. Only conventional 20-byte headers are transmitted;
// incoming variable header options are handled by the bounded reassembler.
func FragmentIPv4(frame []byte, mtu int) ([][]byte, error) {
	if len(frame) < 20 || frame[0] != 0x45 || int(binary.BigEndian.Uint16(frame[2:4])) != len(frame) || len(frame) > 65535 || mtu < 68 || mtu > 65535 || Checksum(frame[:20]) != 0 || binary.BigEndian.Uint16(frame[6:8])&0xbfff != 0 {
		return nil, ErrPacket
	}
	if len(frame) <= mtu {
		return [][]byte{frame}, nil
	}
	if binary.BigEndian.Uint16(frame[6:8])&0x4000 != 0 {
		return nil, ErrMTU
	}
	unit := (mtu - 20) &^ 7
	body := frame[20:]
	if (len(body)+unit-1)/unit > maxFragmentParts {
		return nil, ErrMTU
	}
	parts := make([][]byte, 0, (len(body)+unit-1)/unit)
	for offset := 0; offset < len(body); offset += unit {
		size := unit
		if size > len(body)-offset {
			size = len(body) - offset
		}
		part := make([]byte, 20+size)
		copy(part, frame[:20])
		copy(part[20:], body[offset:offset+size])
		flags := uint16(offset / 8)
		if offset+size < len(body) {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(part[2:4], uint16(len(part)))
		binary.BigEndian.PutUint16(part[6:8], flags)
		part[10], part[11] = 0, 0
		binary.BigEndian.PutUint16(part[10:12], Checksum(part[:20]))
		parts = append(parts, part)
	}
	return parts, nil
}
