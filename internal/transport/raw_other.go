//go:build !linux

// Linux-only raw carrier guard by t.me/ir_spoof.
package transport

import (
	"context"
	"errors"
	"net"
	"netrix.local/ir_spoof/internal/config"
)

func dialRaw(context.Context, *config.Config, config.Path) (net.Conn, error) {
	return nil, errors.New("rawsocket requires Linux")
}
func listenRaw(context.Context, *config.Config, string) (net.Listener, error) {
	return nil, errors.New("rawsocket requires Linux")
}
func ValidateRaw(*config.Config) error { return errors.New("rawsocket requires Linux") }
