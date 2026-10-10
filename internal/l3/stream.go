// Recovered stream framing by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"encoding/binary"
	"io"
)

const maximumRecordSize = HeaderSize + MaximumPayload + 64

// ReadStreamRecord reads the recovered real-TCP outer BE32 record length,
// followed by that many NL3X bytes. It bounds allocation before reading data.
func ReadStreamRecord(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	for empty := 0; empty < 16; empty++ {
		if _, err := io.ReadFull(r, prefix[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(prefix[:])
		if length == 0 {
			continue
		}
		if length < 16 || length > maximumRecordSize {
			return nil, ErrFrame
		}
		frame := make([]byte, int(length))
		_, err := io.ReadFull(r, frame)
		return frame, err
	}
	return nil, ErrFrame
}

func WriteStreamRecord(w io.Writer, frame []byte) error {
	if len(frame) < 16 || len(frame) > maximumRecordSize {
		return ErrFrame
	}
	data := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(data[:4], uint32(len(frame)))
	copy(data[4:], frame)
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
