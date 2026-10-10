// Firewall plan verification by ir_spoof; https://t.me/ir_spoof.
package firewall

import (
	"reflect"
	"strings"
	"testing"
)

func TestScopedRulesAndDefaults(t *testing.T) {
	o, err := normalized(Options{Interface: "nxtun0", LocalCIDR: "198.18.0.1/30", Remote: "198.18.0.2/30"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Destination != "198.18.0.1" || !reflect.DeepEqual(o.Ports, []int{500, 1701, 4500}) {
		t.Fatalf("defaults: %+v", o)
	}
	plan := rules(o, "012345abcdef")
	if len(plan) != 8 {
		t.Fatal("unexpected rule count", len(plan))
	}
	all := ""
	for _, step := range plan {
		all += strings.Join(step.add, " ") + "\n"
	}
	for _, want := range []string{"DNAT --to-destination 198.18.0.1:500", "-o nxtun0 -d 198.18.0.1/32", "--dports 500,1701,4500 -j MASQUERADE", "ir_spoof:012345abcdef"} {
		if !strings.Contains(all, want) {
			t.Fatal("missing scoped rule", want)
		}
	}
	for _, step := range plan {
		if len(step.remove) != 0 && step.remove[2] == "-X" && !strings.HasPrefix(step.remove[3], "IRS_L2") {
			t.Fatal("cleanup outside owned chains")
		}
	}
}

func TestInvalidOptionsDoNotPlanCommands(t *testing.T) {
	base := Options{Interface: "nxtun0", LocalCIDR: "198.18.0.1/30", Remote: "198.18.0.2"}
	for _, mutate := range []func(*Options){func(o *Options) { o.Interface = "bad;cmd" }, func(o *Options) { o.Destination = "example.invalid" }, func(o *Options) { o.Ports = []int{0} }, func(o *Options) { o.Destination = "198.18.0.999" }, func(o *Options) { o.Remote = "::1" }} {
		o := base
		mutate(&o)
		if Validate(o) == nil {
			t.Fatal("invalid options admitted")
		}
	}
}
