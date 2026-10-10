// Independent Linux reconstruction by t.me/ir_spoof.
package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func portRange(s string) (int, int, error) {
	v := strings.Split(s, "-")
	if len(v) > 2 {
		return 0, 0, fmt.Errorf("invalid port range")
	}
	lo, e := strconv.Atoi(v[0])
	if e != nil || lo < 1 || lo > 65535 {
		return 0, 0, fmt.Errorf("invalid port")
	}
	hi := lo
	if len(v) == 2 {
		hi, e = strconv.Atoi(v[1])
		if e != nil || hi < lo || hi > 65535 || hi-lo > 4095 {
			return 0, 0, fmt.Errorf("invalid port range")
		}
	}
	return lo, hi, nil
}
func splitPorts(s string) ([]string, error) {
	var result []string
	start, level := 0, 0
	for i, r := range s {
		switch r {
		case '[':
			level++
		case ']':
			level--
			if level < 0 {
				return nil, fmt.Errorf("invalid address brackets")
			}
		case ':':
			if level == 0 {
				result = append(result, strings.Trim(s[start:i], "[]"))
				start = i + 1
			}
		}
	}
	if level != 0 {
		return nil, fmt.Errorf("invalid address brackets")
	}
	return append(result, strings.Trim(s[start:], "[]")), nil
}
func expand(v any, kind string) ([]Mapping, error) {
	s := fmt.Sprint(v)
	if strings.Contains(s, "=") {
		sides := strings.Split(s, "=")
		if len(sides) != 2 {
			return nil, fmt.Errorf("invalid mapping")
		}
		bh, bp, err := net.SplitHostPort(sides[0])
		if err != nil {
			bh = ""
			bp = sides[0]
			if _, _, err = portRange(bp); err != nil {
				return nil, fmt.Errorf("invalid mapping bind")
			}
		}
		th, tp, err := net.SplitHostPort(sides[1])
		if err != nil {
			return nil, fmt.Errorf("invalid mapping target")
		}
		return expand(net.JoinHostPort(bh, bp)+":"+net.JoinHostPort(th, tp), kind)
	}
	if strings.Contains(s, "->") {
		pair := strings.Split(s, "->")
		if len(pair) != 2 || !validAddr(pair[0]) || !validAddr(pair[1]) {
			return nil, fmt.Errorf("invalid mapping")
		}
		return []Mapping{{kind, pair[0], pair[1]}}, nil
	}
	f, e := splitPorts(s)
	if e != nil {
		return nil, e
	}
	bindIP, targetIP, bindPort, targetPort := "", "127.0.0.1", "", ""
	switch len(f) {
	case 1:
		bindPort, targetPort = f[0], f[0]
	case 2:
		if _, _, e := portRange(f[0]); e == nil {
			bindPort, targetPort = f[0], f[1]
		} else {
			bindIP, bindPort, targetPort = f[0], f[1], f[1]
		}
	case 3:
		if _, _, e := portRange(f[0]); e == nil {
			bindPort, targetIP, targetPort = f[0], f[1], f[2]
		} else {
			bindIP, bindPort, targetPort = f[0], f[1], f[2]
		}
	case 4:
		bindIP, bindPort, targetIP, targetPort = f[0], f[1], f[2], f[3]
	default:
		return nil, fmt.Errorf("invalid mapping; use maps for complex endpoints")
	}
	lo, hi, e := portRange(bindPort)
	if e != nil {
		return nil, e
	}
	tl, th, e := portRange(targetPort)
	if e != nil {
		return nil, e
	}
	if th != tl && th-tl != hi-lo {
		return nil, fmt.Errorf("mapping ranges must have equal sizes")
	}
	if th == tl && hi > lo && targetPort == bindPort {
		th = tl + hi - lo
	}
	out := make([]Mapping, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		t := tl
		if th > tl {
			t += p - lo
		}
		m := Mapping{kind, net.JoinHostPort(bindIP, strconv.Itoa(p)), net.JoinHostPort(targetIP, strconv.Itoa(t))}
		if !validAddr(m.Bind) || !validAddr(m.Target) {
			return nil, fmt.Errorf("invalid mapping endpoint")
		}
		out = append(out, m)
	}
	return out, nil
}
func (c *Config) Mappings() ([]Mapping, error) {
	out := append([]Mapping(nil), c.Maps...)
	if len(out) > 4096 {
		return nil, fmt.Errorf("too many port mappings")
	}
	for _, items := range []struct {
		kind string
		v    []any
	}{{"tcp", c.TCPPorts}, {"udp", c.UDPPorts}} {
		for _, v := range items.v {
			ms, e := expand(v, items.kind)
			if e != nil {
				return nil, e
			}
			out = append(out, ms...)
			if len(out) > 4096 {
				return nil, fmt.Errorf("too many port mappings")
			}
		}
	}
	seen := map[string]bool{}
	for _, m := range out {
		k := m.Type + "/" + m.Bind
		if seen[k] {
			return nil, fmt.Errorf("duplicate listener mapping")
		}
		seen[k] = true
	}
	return out, nil
}
