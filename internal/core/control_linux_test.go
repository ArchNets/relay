//go:build linux

// Independent Linux reconstruction by t.me/ir_spoof.
package core

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
	"netrix.local/ir_spoof/internal/config"
)

func TestControlDispatchAcceptsSingleFieldHeader(t *testing.T) {
	a, b := net.Pipe()
	server, err := smux.Server(a, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := smux.Client(b, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := &Engine{ctx: ctx, Config: &config.Config{DialTimeout: 2}}
	done := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream()
		if err == nil {
			defer stream.Close()
			engine.handleStream(stream)
		}
		done <- err
	}()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(stream, "CTRL\nPING 1896781234567890123\n"); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil || got != "PONG 1896781234567890123\n" {
		t.Fatalf("control dispatch reply = %q, %v", got, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control dispatch did not stop on cancellation")
	}
}
