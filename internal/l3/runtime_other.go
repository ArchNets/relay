//go:build !linux

// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"context"
	"errors"
	"log"

	"netrix.local/ir_spoof/internal/config"
)

func Run(context.Context, *config.Config, *log.Logger) error {
	return errors.New("l3: tunnel runtime requires Linux")
}
