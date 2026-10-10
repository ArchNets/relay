//go:build linux

// TCP response-after-request-EOF regression check by t.me/ir_spoof.
package core

import (
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	x, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	y, err := l.AcceptTCP()
	if err != nil {
		x.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close(); y.Close() })
	x.SetDeadline(time.Now().Add(5 * time.Second))
	y.SetDeadline(time.Now().Add(5 * time.Second))
	return x, y
}

func TestBridgePreservesResponseAfterRequestEOF(t *testing.T) {
	app, front := tcpPair(t)
	back, service := tcpPair(t)
	finished := make(chan struct{})
	go func() { bridge(front, back); close(finished) }()
	serviceResult := make(chan error, 1)
	go func() {
		request, err := io.ReadAll(service)
		if err == nil && string(request) != "request" {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = service.Write([]byte("response after EOF"))
		}
		if err == nil {
			err = service.CloseWrite()
		}
		serviceResult <- err
	}()
	if _, err := app.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(app)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response after EOF" {
		t.Fatalf("truncated response: %q", response)
	}
	if err := <-serviceResult; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("bridge did not finish")
	}
}
