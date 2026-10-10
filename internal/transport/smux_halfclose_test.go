// Response-after-EOF preservation regression by ir_spoof; https://t.me/ir_spoof.
package transport

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestSMUXHalfCloseRetainsResponseForDelayedReader(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("version%d-writeTo%t", version, optimized), func(t *testing.T) {
				a, b := net.Pipe()
				settings := smux.DefaultConfig()
				settings.Version, settings.KeepAliveDisabled = version, true
				client, err := smux.Client(a, settings)
				if err != nil {
					t.Fatal(err)
				}
				server, err := smux.Server(b, settings)
				if err != nil {
					client.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close(); server.Close() })
				response := bytes.Repeat([]byte("ir_spoof complete response after EOF\n"), 2000)
				finished := make(chan error, 1)
				go func() {
					stream, e := server.AcceptStream()
					if e != nil {
						finished <- e
						return
					}
					stream.SetDeadline(time.Now().Add(5 * time.Second))
					request, e := io.ReadAll(stream)
					if e != nil {
						finished <- e
						return
					}
					if !bytes.Equal(request, []byte("request")) {
						finished <- fmt.Errorf("request mismatch")
						return
					}
					if _, e = stream.Write(response); e != nil {
						finished <- e
						return
					}
					finished <- stream.CloseWrite()
				}()
				stream, err := client.OpenStream()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { stream.Close() })
				stream.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = stream.Write([]byte("request")); err != nil {
					t.Fatal(err)
				}
				if err = stream.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err = <-finished; err != nil {
					t.Fatal(err)
				}
				// Deliberately let the response FIN arrive before reading data.
				time.Sleep(50 * time.Millisecond)
				var received []byte
				if optimized {
					var result bytes.Buffer
					_, err = io.Copy(&result, stream)
					received = result.Bytes()
				} else {
					received, err = io.ReadAll(stream)
				}
				if err != nil || !bytes.Equal(received, response) {
					t.Fatalf("response lost: got %d of %d bytes, error %v", len(received), len(response), err)
				}
				if client.NumStreams() != 0 {
					t.Fatal("drained half-closed stream remains registered")
				}
			})
		}
	}
}
