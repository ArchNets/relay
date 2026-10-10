// Configuration interface checks by t.me/ir_spoof.
package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMappings(t *testing.T) {
	for _, tc := range []struct {
		input any
		want  []Mapping
	}{{443, []Mapping{{"tcp", ":443", "127.0.0.1:443"}}}, {"4000-4002:5000-5002", []Mapping{{"tcp", ":4000", "127.0.0.1:5000"}, {"tcp", ":4001", "127.0.0.1:5001"}, {"tcp", ":4002", "127.0.0.1:5002"}}}, {"127.0.0.1:4000:127.0.0.1:5000", []Mapping{{"tcp", "127.0.0.1:4000", "127.0.0.1:5000"}}}, {"[::1]:4000:[::1]:5000", []Mapping{{"tcp", "[::1]:4000", "[::1]:5000"}}}, {"127.0.0.1:4000->[::1]:5000", []Mapping{{"tcp", "127.0.0.1:4000", "[::1]:5000"}}}} {
		got, err := expand(tc.input, "tcp")
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%v => %v, %v", tc.input, got, err)
		}
	}
	for _, bad := range []string{"0", "65536", "6000-1", "1-6000", "12:1-5", "[::1:5", "4000-4001:5000-5002"} {
		if _, err := expand(bad, "udp"); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
func TestLoadStrictAndNeutralErrors(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private-test.json")
	good := `{"mode":"server","listen":"127.0.0.1:4000","tcp_ports":["4001:5000"]}`
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.SMUX.MuxCon != 8 || c.KCP.MTU != 1350 {
		t.Fatal("balanced defaults lost")
	}
	for _, bad := range []string{`{"mode":"server","listen":"127.0.0.1:4000","unknown":true}`, good + "\n---\n{}", `{"mode":"server","listen":"127.0.0.1:4000","tcp_ports":[0]}`} {
		os.WriteFile(path, []byte(bad), 0600)
		_, err = Load(path)
		if err == nil {
			t.Fatal("invalid configuration accepted")
		}
		if strings.Contains(err.Error(), root) {
			t.Fatal("error disclosed a file path")
		}
	}
	_, err = Load(filepath.Join(root, "missing"))
	if err == nil || strings.Contains(err.Error(), root) {
		t.Fatal("file error disclosed path")
	}
}
func TestDuplicateMappingRejected(t *testing.T) {
	c := &Config{Mode: "server", Listen: "127.0.0.1:4000", TCPPorts: []any{4001, 4001}}
	c.Defaults()
	if c.Validate() == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestReferenceEqualsMapping(t *testing.T) {
	got, err := expand("127.0.0.1:18080=127.0.0.1:8080", "tcp")
	want := []Mapping{{"tcp", "127.0.0.1:18080", "127.0.0.1:8080"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%v %v", got, err)
	}
	got, err = expand("18080=127.0.0.1:8080", "tcp")
	if err != nil || got[0].Bind != ":18080" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestNoFalseAuthenticationOrUnsupportedTuning(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.PSK = "two tokens" },
		func(c *Config) { c.PSK = "two\u2003tokens" },
		func(c *Config) { c.Encryption.Enabled = true },
		func(c *Config) { c.Reality = &Reality{PublicKey: "unverified"} },
		func(c *Config) { c.Reality = &Reality{Fingerprint: "typo"} },
		func(c *Config) { c.Advanced.AntiDpiDelayMs = 10 },
		func(c *Config) { c.Advanced.StreamTimeout = 10 },
	} {
		c := &Config{Mode: "server", Listen: "127.0.0.1:4000"}
		c.Defaults()
		change(c)
		if c.Validate() == nil {
			t.Fatal("configuration claimed unsupported authentication or tuning")
		}
	}
}
