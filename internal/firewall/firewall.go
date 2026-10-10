// Owned Linux L2TP forwarding by ir_spoof; https://t.me/ir_spoof.
package firewall

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
)

// Options describes UDP DNAT through a TUN interface. Forwarding and any
// host-wide firewall policy are explicit prerequisites, not changed here.
type Options struct {
	Interface   string
	LocalCIDR   string
	Remote      string
	Ports       []int
	Destination string
}

var interfaceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)

func address(value string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		if prefix, prefixErr := netip.ParsePrefix(value); prefixErr == nil {
			ip = prefix.Addr()
			err = nil
		}
	}
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") {
		return netip.Addr{}, errors.New("firewall: literal unicast IPv4 address required")
	}
	return ip, nil
}

func normalized(o Options) (Options, error) {
	if !interfaceName.MatchString(o.Interface) {
		return o, errors.New("firewall: invalid owned TUN interface")
	}
	local, err := netip.ParsePrefix(o.LocalCIDR)
	if err != nil || !local.Addr().Is4() || local.Addr().IsUnspecified() || local.Addr().IsMulticast() {
		return o, errors.New("firewall: local IPv4 prefix required")
	}
	if o.Remote != "" {
		if _, err = address(o.Remote); err != nil {
			return o, err
		}
	}
	if o.Destination == "" {
		o.Destination = local.Addr().String()
	}
	dst, err := address(o.Destination)
	if err != nil {
		return o, errors.New("firewall: literal L2TP destination required")
	}
	o.Destination = dst.String()
	o.Ports = append([]int(nil), o.Ports...)
	if len(o.Ports) == 0 {
		o.Ports = []int{500, 4500, 1701}
	}
	if len(o.Ports) > 256 {
		return o, errors.New("firewall: at most 256 L2TP ports")
	}
	for _, port := range o.Ports {
		if port < 1 || port > 65535 {
			return o, errors.New("firewall: invalid L2TP port")
		}
	}
	slices.Sort(o.Ports)
	o.Ports = slices.Compact(o.Ports)
	return o, nil
}

// Validate checks all options without executing commands or reading host state.
func Validate(o Options) error { _, err := normalized(o); return err }
