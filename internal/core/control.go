// Independent Linux reconstruction by t.me/ir_spoof.
package core

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"

	"netrix.local/ir_spoof/internal/wire"
)

const controlIdleTimeout = 10 * time.Minute

// The initial CTRL line has already been consumed. Keep the same buffered
// reader so a PING coalesced with that line is not discarded. The recovered
// reply echoes the trimmed suffix; it does not parse or replace the timestamp.
func replyControl(ctx context.Context, conn net.Conn, reader *bufio.Reader, idle time.Duration) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	for ctx.Err() == nil {
		if conn.SetReadDeadline(time.Now().Add(idle)) != nil {
			return
		}
		line, err := wire.Line(reader, 512)
		if err != nil {
			return
		}
		if !strings.HasPrefix(line, "PING ") {
			continue
		}
		if conn.SetWriteDeadline(time.Now().Add(idle)) != nil {
			return
		}
		if wire.WriteAll(conn, []byte("PONG "+strings.TrimSpace(line[5:])+"\n")) != nil {
			return
		}
	}
}
