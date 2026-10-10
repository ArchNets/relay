//go:build linux

// Linux firewall lifecycle by ir_spoof; https://t.me/ir_spoof.
package firewall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type installation struct {
	executable string
	steps      []ruleStep
	once       sync.Once
	err        error
}

func command(ctx context.Context, path string, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, append([]string{"-w", "2"}, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	// Command output may disclose a host configuration path; errors remain
	// bounded and neutral. Commands receive validated argument vectors only.
	if err := cmd.Run(); err != nil {
		return errors.New("firewall: owned iptables rule operation failed")
	}
	return nil
}

func (i *installation) Close() error {
	i.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for n := len(i.steps) - 1; n >= 0; n-- {
			step := i.steps[n]
			if len(step.remove) == 0 {
				continue
			}
			if len(step.remove) == 4 && step.remove[2] == "-X" {
				i.err = errors.Join(i.err, command(ctx, i.executable, []string{"-t", "nat", "-F", step.remove[3]}))
			}
			i.err = errors.Join(i.err, command(ctx, i.executable, step.remove))
		}
	})
	return i.err
}

// Install adds isolated NAT chains and jumps. It requires the administrator to
// enable IPv4 forwarding and allow routed UDP; it never changes those globals.
// Close removes only the successfully created rules from this invocation.
func Install(ctx context.Context, o Options) (io.Closer, error) {
	o, err := normalized(o)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	local, _ := netip.ParsePrefix(o.LocalCIDR)
	if o.Destination != local.Addr().String() {
		forward, forwardErr := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if forwardErr != nil || strings.TrimSpace(string(forward)) != "1" {
			return nil, errors.New("firewall: routed L2TP requires net.ipv4.ip_forward=1; enable it explicitly")
		}
	}
	path, err := trustedIPTables()
	if err != nil {
		return nil, errors.New("firewall: L2TP requires installed iptables")
	}
	var random [6]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, errors.New("firewall: cannot create owned rule identifier")
	}
	i := &installation{executable: path}
	for _, step := range rules(o, hex.EncodeToString(random[:])) {
		if err = command(ctx, path, step.add); err != nil {
			cleanup := i.Close()
			return nil, errors.Join(err, cleanup)
		}
		i.steps = append(i.steps, step)
	}
	return i, nil
}

// Only administrator-owned conventional system helpers may run with the
// privileges used for firewall setup. Preserve the iptables symlink's argv[0]
// so the trusted xtables multi-call executable selects its correct applet.
func trustedIPTables() (string, error) {
	for _, candidate := range []string{"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "/bin/iptables"} {
		path, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if unix.Stat(path, &stat) != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 || stat.Mode&0111 == 0 {
			continue
		}
		trusted := true
		for _, start := range []string{filepath.Dir(path), filepath.Dir(candidate)} {
			for directory := start; ; directory = filepath.Dir(directory) {
				if unix.Stat(directory, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
					trusted = false
					break
				}
				if directory == filepath.Dir(directory) {
					break
				}
			}
			if !trusted {
				break
			}
		}
		if trusted {
			return candidate, nil
		}
	}
	return "", errors.New("firewall: trusted root-owned system iptables is required")
}
