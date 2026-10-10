// Independent Linux reconstruction by t.me/ir_spoof.
package core

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"netrix.local/ir_spoof/internal/wire"
)

func TestControlRepliesPreserveLookaheadAndTimestamp(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		reader := bufio.NewReader(server)
		line, err := wire.Line(reader, 512)
		if err != nil || line != "CTRL" {
			return
		}
		replyControl(ctx, server, reader, time.Second)
	}()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	// A single write intentionally includes the header, unrelated input and
	// multiple pings. Reading from a new bufio.Reader would lose these bytes.
	if _, err := io.WriteString(client, "CTRL\nnoise\nPING 1896781234567890123\nPING   opaque-token  \n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	for _, want := range []string{"PONG 1896781234567890123\n", "PONG opaque-token\n"} {
		got, err := reader.ReadString('\n')
		if err != nil || got != want {
			t.Fatalf("reply = %q, %v; want %q", got, err, want)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control handler remained blocked after cancellation")
	}
}

func TestControlOversizedLineCloses(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		replyControl(context.Background(), server, bufio.NewReaderSize(server, 32), time.Second)
	}()
	client.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(client, "PING "+strings.Repeat("x", 512)+"\n")
	var reply [1]byte
	if n, err := client.Read(reply[:]); n != 0 || err == nil {
		t.Fatalf("oversized control line accepted: %d, %v", n, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("oversized input left handler running")
	}
}

func TestControlIdleDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		replyControl(context.Background(), server, bufio.NewReader(server), 20*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle control stream did not time out")
	}
}
