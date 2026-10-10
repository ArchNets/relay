//go:build linux

// Bounded reconnect retention checks by t.me/ir_spoof.
package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func retainedSessionPair(t *testing.T) (*smux.Session, *smux.Session) {
	t.Helper()
	a, b := net.Pipe()
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	client, err := smux.Client(a, config)
	if err != nil {
		a.Close()
		b.Close()
		t.Fatal(err)
	}
	server, err := smux.Server(b, config)
	if err != nil {
		client.Close()
		b.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func TestPoolPrunesClosedSessionsAndClearsBackingReferences(t *testing.T) {
	for _, operation := range []string{"add", "count", "open"} {
		t.Run(operation, func(t *testing.T) {
			p := newPool()
			t.Cleanup(p.close)
			live, _ := retainedSessionPair(t)
			oldA, oldPeerA := retainedSessionPair(t)
			oldB, oldPeerB := retainedSessionPair(t)
			p.add(oldA)
			p.add(live)
			p.add(oldB)
			backing := p.items
			oldA.Close()
			oldPeerA.Close()
			oldB.Close()
			oldPeerB.Close()
			switch operation {
			case "add":
				added, _ := retainedSessionPair(t)
				p.add(added)
			case "count":
				if p.count() != 1 {
					t.Fatal("closed sessions counted as live")
				}
			case "open":
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				stream, err := p.open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				stream.Close()
			}
			for i, session := range backing {
				if session == oldA || session == oldB {
					t.Fatalf("closed peer retained in backing slot %d", i)
				}
			}
			if p.items[0] != live {
				t.Fatal("pruning changed live peer order")
			}
		})
	}
}

func TestBackendOnlyPoolReconnectsRemainBoundedWithoutOpeningStreams(t *testing.T) {
	p := newPool()
	t.Cleanup(p.close)
	for i := 0; i < 128; i++ {
		session, peer := retainedSessionPair(t)
		p.add(session)
		if len(p.items) != 1 {
			t.Fatalf("backend-only reconnect retained %d peers", len(p.items))
		}
		session.Close()
		peer.Close()
	}
	backing := p.items
	if p.count() != 0 {
		t.Fatal("ended backend-only sessions remain active")
	}
	if backing[0] != nil {
		t.Fatal("closed session remains referenced after count")
	}
}
