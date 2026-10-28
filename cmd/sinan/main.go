// Command sinan keeps proxy traffic off an untrusted Wi-Fi by steering it
// through phone tethering, while everything else keeps using the Wi-Fi.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/SimonShiki/sinan/internal/config"
	"github.com/SimonShiki/sinan/internal/daemon"
)

func main() {
	path := flag.String("c", "/etc/sinan/config.yaml", "config file")
	check := flag.Bool("check", false, "print detected uplinks and endpoint table, verify the eBPF programs, then exit")
	flag.Parse()

	if err := run(*path, *check); err != nil {
		fmt.Fprintln(os.Stderr, "sinan:", err)
		os.Exit(1)
	}
}

func run(path string, check bool) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	d := daemon.New(cfg)
	if err := d.Validate(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if check {
		return d.Check(ctx)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	return d.Run(ctx)
}
