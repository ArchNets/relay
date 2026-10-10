//go:build linux

// Independent Linux reconstruction by t.me/ir_spoof.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"netrix.local/ir_spoof/internal/config"
	"netrix.local/ir_spoof/internal/core"
	"netrix.local/ir_spoof/internal/firewall"
	"netrix.local/ir_spoof/internal/l3"
	"netrix.local/ir_spoof/internal/transport"
	"os"
	"os/signal"
	"syscall"
)

const version = "0.1.0"

func main() {
	flags := flag.NewFlagSet("netrix", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	path := flags.String("config", "", "local YAML/JSON configuration")
	check := flags.Bool("check", false, "validate without network access")
	show := flags.Bool("version", false, "show independent build version")
	legacy := flags.Bool("compat-v3", false, "explicit reference-v3 encrypted record compatibility")
	args := os.Args[1:]
	requestedMode := ""
	if len(args) > 0 && (args[0] == "server" || args[0] == "client") {
		requestedMode = args[0]
		args = args[1:]
	}
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *show {
		fmt.Println("netrix ir_spoof " + version + " linux; independent reconstruction")
		return
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "Netrix ir_spoof: use netrix -config FILE [-check] [-compat-v3]")
		os.Exit(2)
	}
	c, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if requestedMode != "" && requestedMode != c.Mode {
		fmt.Fprintln(os.Stderr, "requested role disagrees with configuration mode")
		os.Exit(2)
	}
	if *check {
		if err = transport.ValidateRaw(c); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if c.Tun != nil && c.Tun.ForwardL2TP {
			if err = firewall.Validate(firewall.Options{Interface: c.Tun.Name, LocalCIDR: c.Tun.Local, Remote: c.Tun.Remote, Ports: c.Tun.L2TPPorts, Destination: c.Tun.L2TPDestIP}); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}
		if c.Transport == "l3" {
			if err = l3.Validate(c); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}
		fmt.Println("configuration valid; no network activity")
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	e := core.Engine{Config: c, Legacy: *legacy, Logger: log.New(os.Stderr, "netrix: ", 0)}
	if err = e.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
