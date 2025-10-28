package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-tcpconnlat/internal/probe"
)

var (
	minLatency = flag.Int("min", 0, "Minimum latency (in microseconds) to filter")
    pid   = flag.Int("pid", 0, "Process ID to filter")
)

func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nCaught SIGINT... Exiting")
		cancel()
	}()
}

func main() {
	flag.Parse()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)

	if err := probe.Run(ctx, *minLatency, *pid); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}
}