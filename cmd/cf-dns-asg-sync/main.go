package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	sync "github.com/rkoster/cf-dns-asg-sync"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet("cf-dns-asg-sync", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to the YAML policy (required)")
	dryRun := flags.Bool("dry-run", false, "show planned ASG changes without applying them")
	prune := flags.Bool("prune-existing-asgs", false, "remove unused existing ASG bindings in managed spaces and delete unbound groups")
	credentials := flags.Bool("client-credentials", false, "use CF_USERNAME and CF_PASSWORD as a UAA client ID and secret")
	ipv6 := flags.Bool("ipv6", false, "resolve AAAA records as well as A records")
	timeout := flags.Duration("timeout", 3*time.Minute, "overall reconciliation timeout")
	var private []netip.Prefix
	flags.Func("allow-private-cidr", "allow resolved private addresses within this CIDR (repeatable)", func(value string) error {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		private = append(private, p.Masked())
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *path == "" || flags.NArg() != 0 || *timeout <= 0 {
		return fmt.Errorf("provide --config and a positive --timeout; see --help")
	}
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer f.Close()
	policy, err := sync.ParsePolicy(f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	cf, err := sync.NewCloudFoundry(os.Getenv, *credentials)
	if err != nil {
		return err
	}
	return sync.SyncWithOptions(ctx, cf, policy, resolver, sync.DNSOptions{IPv6: *ipv6, PrivateCIDRs: private}, sync.SyncOptions{DryRun: *dryRun, PruneExistingASGs: *prune}, out)
}
