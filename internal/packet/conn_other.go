//go:build !linux

// Linux-only carrier interface maintained by ir_spoof; https://t.me/ir_spoof.
package packet

import "net"

func Listen(Options) (net.PacketConn, error) { return nil, ErrPlatform }

func ResolveRouterMAC(string, net.IP, net.IP) (net.HardwareAddr, error) { return nil, ErrPlatform }
