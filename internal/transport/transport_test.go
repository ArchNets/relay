// Independent transport integration checks by t.me/ir_spoof.
package transport

import (
	"context"
	"crypto/tls"
	"github.com/gorilla/websocket"
	"io"
	"netrix.local/ir_spoof/internal/config"
	"testing"
	"time"
)

// Check the recovered public endpoint with an independent WebSocket dialer,
// so a shared wrong path in our listener and Dial cannot mask incompatibility.
func TestWebSocketRecoveredEndpoint(t *testing.T) {
	for _, carrier := range []string{"wsmux", "wssmux"} {
		t.Run(carrier, func(t *testing.T) {
			c := &config.Config{Transport: carrier}
			c.Defaults()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			l, err := Listen(ctx, c, "127.0.0.1:0", carrier)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			scheme := "ws"
			if carrier == "wssmux" {
				scheme = "wss"
			}
			d := websocket.Dialer{HandshakeTimeout: 5 * time.Second, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			if x, response, err := d.DialContext(ctx, scheme+"://"+l.Addr().String()+"/", nil); err == nil {
				x.Close()
				t.Fatal("unexpected WebSocket endpoint accepted")
			} else if response == nil || response.StatusCode != 404 {
				status := 0
				if response != nil {
					status = response.StatusCode
					response.Body.Close()
				}
				t.Fatalf("unexpected endpoint response: status=%d error=%v", status, err)
			} else {
				response.Body.Close()
			}
			x, response, err := d.DialContext(ctx, scheme+"://"+l.Addr().String()+"/ws", nil)
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			defer x.Close()
			accepted, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			accepted.SetDeadline(time.Now().Add(5 * time.Second))
			if err := x.WriteMessage(websocket.BinaryMessage, []byte("endpoint")); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 8)
			if _, err := io.ReadFull(accepted, payload); err != nil {
				t.Fatal(err)
			}
			if string(payload) != "endpoint" {
				t.Fatal("payload changed")
			}
		})
	}
}

func TestConfiguredTransports(t *testing.T) {
	for _, kind := range []string{"tcpmux", "tlsmux", "realitymux", "kcpmux", "wsmux", "wssmux"} {
		t.Run(kind, func(t *testing.T) {
			c := &config.Config{Mode: "server", Listen: "127.0.0.1:1", Transport: kind}
			c.Defaults()
			yes := true
			c.Advanced.TLSInsecureSkipVerify = &yes
			c.Reality = &config.Reality{Fingerprint: "chrome", SNI: "localhost"}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			l, err := Listen(ctx, c, "127.0.0.1:0", kind)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				x, err := l.Accept()
				if err != nil {
					done <- err
					return
				}
				defer x.Close()
				x.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 4096)
				_, err = io.ReadFull(x, b)
				if err == nil {
					_, err = x.Write(b)
				}
				// KCP writes queue data; wait for an application acknowledgement
				// before closing, so the test does not discard an unflushed reply.
				if err == nil {
					var ack [1]byte
					_, err = io.ReadFull(x, ack[:])
				}
				done <- err
			}()
			x, err := Dial(ctx, Options{Config: c, Path: config.Path{Addr: l.Addr().String(), Transport: kind, DialTimeout: 5, Reality: c.Reality}})
			if err != nil {
				t.Fatal(err)
			}
			defer x.Close()
			x.SetDeadline(time.Now().Add(5 * time.Second))
			want := make([]byte, 4096)
			for i := range want {
				want[i] = byte(i * 31)
			}
			if _, err = x.Write(want); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			if _, err = io.ReadFull(x, got); err != nil {
				t.Fatal(err)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatal("payload changed")
				}
			}
			if _, err = x.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
