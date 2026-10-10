// Duplex, replacement and reconnect regression checks by t.me/ir_spoof.
package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"netrix.local/ir_spoof/internal/wire"
)

type testPacketQueue struct {
	input, output chan []byte
	closed        chan struct{}
	once          sync.Once
}

func newTestPacketQueue() *testPacketQueue {
	return &testPacketQueue{input: make(chan []byte, 4), output: make(chan []byte, 4), closed: make(chan struct{})}
}
func (q *testPacketQueue) Read(p []byte) (int, error) {
	select {
	case packet := <-q.input:
		return copy(p, packet), nil
	case <-q.closed:
		return 0, io.ErrClosedPipe
	}
}
func (q *testPacketQueue) Write(p []byte) (int, error) {
	select {
	case q.output <- append([]byte(nil), p...):
		return len(p), nil
	case <-q.closed:
		return 0, io.ErrClosedPipe
	}
}
func (q *testPacketQueue) Close() error { q.once.Do(func() { close(q.closed) }); return nil }

func testPacket(t *testing.T, q *testPacketQueue, want []byte) {
	t.Helper()
	select {
	case got := <-q.output:
		if !bytes.Equal(got, want) {
			t.Fatalf("packet mismatch: %x != %x", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet did not arrive")
	}
}

func TestTUNOneStreamCarriesBothDirectionsWithDifferentQueueCounts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	pa, pb := newTUNPacketPool(1), newTUNPacketPool(2)
	qa, qb := newTestPacketQueue(), newTestPacketQueue()
	slot := tunSlot{2, 3}
	sa, _ := pa.register(slot, a)
	sb, _ := pb.register(slot, b)
	var workers sync.WaitGroup
	start := func(fn func()) { workers.Add(1); go func() { defer workers.Done(); fn() }() }
	start(func() { pumpTUNPackets(ctx, pa, qa, 0) })
	start(func() { pumpTUNPackets(ctx, pb, qb, 1) })
	start(func() { defer pa.clear(slot, sa); _ = readTUNPackets(qa, a) })
	start(func() { defer pb.clear(slot, sb); _ = readTUNPackets(qb, b) })
	t.Cleanup(func() {
		cancel()
		pa.close()
		pb.close()
		qa.Close()
		qb.Close()
		finished := make(chan struct{})
		go func() { workers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("TUN workers remained blocked on shutdown")
		}
	})
	request, reply := []byte("one complete IP request"), []byte("reply on the same stream")
	qa.input <- request
	testPacket(t, qb, request)
	qb.input <- reply
	testPacket(t, qa, reply)
}

func TestTUNReplacementReconnectsWhileQueueReaderIsIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTUNPacketPool(1)
	queue := newTestPacketQueue()
	old, oldPeer := net.Pipe()
	current, currentPeer := net.Pipe()
	current.SetDeadline(time.Now().Add(5 * time.Second))
	currentPeer.SetDeadline(time.Now().Add(5 * time.Second))
	slot := tunSlot{0, 1}
	previous, _ := pool.register(slot, old)
	pumpFinished := make(chan struct{})
	go func() { pumpTUNPackets(ctx, pool, queue, 0); close(pumpFinished) }()
	t.Cleanup(func() {
		cancel()
		pool.close()
		queue.Close()
		oldPeer.Close()
		currentPeer.Close()
		select {
		case <-pumpFinished:
		case <-time.After(time.Second):
			t.Error("idle queue pump remained blocked")
		}
	})
	replacement, ok := pool.register(slot, current)
	if !ok {
		t.Fatal("replacement rejected")
	}
	pool.clear(slot, previous)
	_, chosen, err := pool.choose(ctx, 0)
	if err != nil || chosen != replacement {
		t.Fatal("stale reader cleared the replacement")
	}
	want := []byte("first packet after idle reconnect")
	queue.input <- want
	got, err := wire.ReadPacket(currentPeer)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("replacement stream did not receive packet: %x, %v", got, err)
	}
}

type yieldingTUNConn struct{ net.Conn }

func (c yieldingTUNConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	runtime.Gosched()
	return n, err
}

func TestTUNPacketWritesCannotInterleaveAcrossLocalQueues(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	pool := newTUNPacketPool(2)
	pool.register(tunSlot{0, 1}, yieldingTUNConn{a})
	t.Cleanup(func() { pool.close(); b.Close() })
	const count = 64
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		index := i
		go func() { results <- pool.write(ctx, index%2, bytes.Repeat([]byte{byte(index)}, 512)) }()
	}
	seen := make(map[byte]bool)
	for i := 0; i < count; i++ {
		packet, err := wire.ReadPacket(b)
		if err != nil || len(packet) != 512 || !bytes.Equal(packet, bytes.Repeat(packet[:1], 512)) || seen[packet[0]] {
			t.Fatalf("interleaved or repeated packet: length %d, error %v", len(packet), err)
		}
		seen[packet[0]] = true
	}
	for i := 0; i < count; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTUNControlBoundsAndSlotCapacity(t *testing.T) {
	for _, text := range []string{"0/1", "1/0", "1/65", "65/64", "2/1", "1/1/1", "x/2"} {
		if _, err := parseTUNSlot(text); err == nil {
			t.Fatalf("invalid control accepted: %s", text)
		}
	}
	if slot, err := parseTUNSlot("64/64"); err != nil || slot != (tunSlot{63, 64}) {
		t.Fatal("maximum valid control rejected")
	}
	pool := newTUNPacketPool(1)
	t.Cleanup(pool.close)
	for i := 0; i < 64; i++ {
		if _, ok := pool.register(tunSlot{i, 64}, newTestPacketQueue()); !ok {
			t.Fatal("bounded valid slot rejected")
		}
	}
	if _, ok := pool.register(tunSlot{0, 63}, newTestPacketQueue()); ok {
		t.Fatal("slot capacity exceeded")
	}
}
