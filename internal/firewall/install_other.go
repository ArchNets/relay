//go:build !linux

// Platform limitation by ir_spoof; https://t.me/ir_spoof.
package firewall

import (
	"context"
	"errors"
	"io"
)

func Install(context.Context, Options) (io.Closer, error) {
	return nil, errors.New("firewall: L2TP forwarding requires Linux")
}
