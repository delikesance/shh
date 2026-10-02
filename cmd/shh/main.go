package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	port := flag.Int("p", 2222, "Port to listen on for SSH connections")
	bind := flag.String("b", "0.0.0.0", "Interface address to bind")
	hostKey := flag.String("k", ".ssh_host_key", "Path to server host private key")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	log.Printf("[shh] Starting encrypted SSH chat daemon on %s (host key: %s)...", addr, *hostKey)

	// Graceful shutdown channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("[shh] Daemon shutting down gracefully...")
}
