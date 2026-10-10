// Scoped firewall rule planning by ir_spoof; https://t.me/ir_spoof.
package firewall

import (
	"strconv"
	"strings"
)

type ruleStep struct{ add, remove []string }

func rules(o Options, token string) []ruleStep {
	pre, post := "IRS_L2PRE_"+token, "IRS_L2POST_"+token
	steps := []ruleStep{
		{[]string{"-t", "nat", "-N", pre}, []string{"-t", "nat", "-X", pre}},
		{[]string{"-t", "nat", "-N", post}, []string{"-t", "nat", "-X", post}},
	}
	for _, port := range o.Ports {
		value := strconv.Itoa(port)
		steps = append(steps, ruleStep{[]string{"-t", "nat", "-A", pre, "-p", "udp", "--dport", value, "-j", "DNAT", "--to-destination", o.Destination + ":" + value}, nil})
	}
	for start := 0; start < len(o.Ports); start += 15 {
		values := make([]string, 0, 15)
		for _, port := range o.Ports[start:min(start+15, len(o.Ports))] {
			values = append(values, strconv.Itoa(port))
		}
		steps = append(steps, ruleStep{[]string{"-t", "nat", "-A", post, "-o", o.Interface, "-d", o.Destination + "/32", "-p", "udp", "-m", "multiport", "--dports", strings.Join(values, ","), "-j", "MASQUERADE"}, nil})
	}
	for _, jump := range []struct{ base, target string }{{"PREROUTING", pre}, {"POSTROUTING", post}} {
		suffix := []string{"-m", "comment", "--comment", "ir_spoof:" + token, "-j", jump.target}
		add := append([]string{"-t", "nat", "-A", jump.base}, suffix...)
		remove := append([]string{"-t", "nat", "-D", jump.base}, suffix...)
		steps = append(steps, ruleStep{add, remove})
	}
	return steps
}
