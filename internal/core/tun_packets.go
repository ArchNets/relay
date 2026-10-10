// Bidirectional TUN stream reconstruction by t.me/ir_spoof.
package core

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"

	"netrix.local/ir_spoof/internal/wire"
)

// The remote queue index and total identify a replaceable bidirectional stream.
// Queue selection is local scheduling; neither a hash nor a queue identifier is
// added to the recovered BE32-length packet framing.
type tunSlot struct{ index, total int }

func parseTUNSlot(text string) (tunSlot, error) {
	parts := strings.Split(text, "/")
	if len(parts) != 2 {
		return tunSlot{}, errors.New("invalid TUN stream index")
	}
	index, err := strconv.Atoi(parts[0])
	total, err2 := strconv.Atoi(parts[1])
	if err != nil || err2 != nil || index < 1 || total < 1 || total > 64 || index > total {
		return tunSlot{}, errors.New("invalid TUN stream index")
	}
	return tunSlot{index - 1, total}, nil
}

type tunPacketStream struct {
	conn    io.ReadWriteCloser
	writeMu sync.Mutex
}

type tunPacketPool struct {
	mu          sync.Mutex
	slots       map[tunSlot]*tunPacketStream
	changed     chan struct{}
	localQueues int
	closed      bool
}

func newTUNPacketPool(localQueues int) *tunPacketPool {
	return &tunPacketPool{slots: make(map[tunSlot]*tunPacketStream), changed: make(chan struct{}), localQueues: localQueues}
}

func (p *tunPacketPool) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *tunPacketPool) register(slot tunSlot, conn io.ReadWriteCloser) (*tunPacketStream, bool) {
	stream := &tunPacketStream{conn: conn}
	p.mu.Lock()
	old := p.slots[slot]
	if p.closed || slot.total < 1 || slot.total > 64 || slot.index < 0 || slot.index >= slot.total || old == nil && len(p.slots) >= 64 {
		p.mu.Unlock()
		conn.Close()
		return nil, false
	}
	p.slots[slot] = stream
	p.notifyLocked()
	p.mu.Unlock()
	if old != nil {
		old.conn.Close()
	}
	return stream, true
}

// An older read loop may finish after its slot was replaced. It must not remove
// the replacement or close its connection.
func (p *tunPacketPool) clear(slot tunSlot, stream *tunPacketStream) {
	p.mu.Lock()
	if p.slots[slot] == stream {
		delete(p.slots, slot)
		p.notifyLocked()
	}
	p.mu.Unlock()
	stream.conn.Close()
}

func (p *tunPacketPool) choose(ctx context.Context, queue int) (tunSlot, *tunPacketStream, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return tunSlot{}, nil, io.ErrClosedPipe
		}
		var selected tunSlot
		var stream *tunPacketStream
		preferred := false
		for slot, candidate := range p.slots {
			matches := slot.index%p.localQueues == queue
			if stream == nil || matches && !preferred || matches == preferred && (slot.index < selected.index || slot.index == selected.index && slot.total < selected.total) {
				selected, stream, preferred = slot, candidate, matches
			}
		}
		changed := p.changed
		p.mu.Unlock()
		if stream != nil {
			return selected, stream, nil
		}
		select {
		case <-ctx.Done():
			return tunSlot{}, nil, ctx.Err()
		case <-changed:
		}
	}
}

func (p *tunPacketPool) write(ctx context.Context, queue int, packet []byte) error {
	for ctx.Err() == nil {
		slot, stream, err := p.choose(ctx, queue)
		if err != nil {
			return err
		}
		// Header and payload are one locked transaction, including when several
		// local queues fall back to the same remote stream.
		stream.writeMu.Lock()
		err = wire.WritePacket(stream.conn, packet)
		stream.writeMu.Unlock()
		if err == nil {
			return nil
		}
		p.clear(slot, stream)
	}
	return ctx.Err()
}

func (p *tunPacketPool) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	streams := p.slots
	p.slots = make(map[tunSlot]*tunPacketStream)
	p.notifyLocked()
	p.mu.Unlock()
	for _, stream := range streams {
		stream.conn.Close()
	}
}

// A device queue has one long-lived reader, independent of stream reconnects.
// Its packet buffer bounds pending application state while no peer is ready.
func pumpTUNPackets(ctx context.Context, pool *tunPacketPool, queue io.Reader, index int) {
	buffer := make([]byte, 65535)
	for ctx.Err() == nil {
		n, err := queue.Read(buffer)
		if err != nil {
			return
		}
		if n > 0 && pool.write(ctx, index, buffer[:n]) != nil {
			return
		}
	}
}

func readTUNPackets(queue io.Writer, reader io.Reader) error {
	for {
		packet, err := wire.ReadPacket(reader)
		if err != nil {
			return err
		}
		n, err := queue.Write(packet)
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
	}
}
