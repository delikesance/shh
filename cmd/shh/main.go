package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"git.delikesance.cloud/delikesance/shh/internal/daemon"
	"git.delikesance.cloud/delikesance/shh/internal/peer"
)

// Default configuration constants
const (
	DefaultBind     = "0.0.0.0"
	DefaultPort     = 2222
	DefaultHostKey  = ".ssh_host_key"
	DefaultLogLevel = "info"
)

// Config represents runtime configuration options for the shh daemon.
type Config struct {
	Bind     string
	Port     int
	HostKey  string
	MOTD     string
	LogLevel string
}

// App encapsulates the daemon server, peer registry, and runtime configuration.
type App struct {
	Config   *Config
	Registry *peer.Registry
	Server   *daemon.Server
}

// ParseConfig parses command-line flags and environment variables into a Config instance.
// Environment variables (SHH_PORT, SHH_BIND, SHH_HOST_KEY, SHH_MOTD, SHH_LOG_LEVEL) serve
// as fallbacks, and explicit command-line flags take highest precedence.
func ParseConfig(args []string, getenv func(string) string) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	cfg := &Config{
		Bind:     DefaultBind,
		Port:     DefaultPort,
		HostKey:  DefaultHostKey,
		MOTD:     "",
		LogLevel: DefaultLogLevel,
	}

	// Read environment variables
	if envBind := getenv("SHH_BIND"); envBind != "" {
		cfg.Bind = envBind
	}
	if envPort := getenv("SHH_PORT"); envPort != "" {
		p, err := strconv.Atoi(envPort)
		if err != nil {
			return nil, fmt.Errorf("invalid SHH_PORT %q: %w", envPort, err)
		}
		cfg.Port = p
	}
	if envHostKey := getenv("SHH_HOST_KEY"); envHostKey != "" {
		cfg.HostKey = envHostKey
	}
	if envMOTD := getenv("SHH_MOTD"); envMOTD != "" {
		cfg.MOTD = envMOTD
	}
	if envLogLevel := getenv("SHH_LOG_LEVEL"); envLogLevel != "" {
		cfg.LogLevel = envLogLevel
	}

	fs := flag.NewFlagSet("shh", flag.ContinueOnError)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: shh [options]\n\n")
		fmt.Fprintf(fs.Output(), "Ephemeral, zero-install encrypted SSH chat daemon.\n\n")
		fmt.Fprintf(fs.Output(), "Options:\n")
		fmt.Fprintf(fs.Output(), "  -b, --bind <address>      Interface address to bind (default: %s, env: SHH_BIND)\n", DefaultBind)
		fmt.Fprintf(fs.Output(), "  -p, --port <port>         Port to listen on (default: %d, env: SHH_PORT)\n", DefaultPort)
		fmt.Fprintf(fs.Output(), "  -k, --host-key <path>     Path to host private key (default: %s, env: SHH_HOST_KEY)\n", DefaultHostKey)
		fmt.Fprintf(fs.Output(), "      --motd <message>      Message of the day displayed on connect\n")
		fmt.Fprintf(fs.Output(), "      --log-level <level>   Log level (debug, info, warn, error) (default: %s)\n", DefaultLogLevel)
		fmt.Fprintf(fs.Output(), "  -h, --help                Show this help message\n")
	}

	// Register short and long flags pointing to same config fields
	fs.StringVar(&cfg.Bind, "b", cfg.Bind, "Interface address to bind")
	fs.StringVar(&cfg.Bind, "bind", cfg.Bind, "Interface address to bind")

	fs.IntVar(&cfg.Port, "p", cfg.Port, "Port to listen on for SSH connections")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "Port to listen on for SSH connections")

	fs.StringVar(&cfg.HostKey, "k", cfg.HostKey, "Path to server host private key")
	fs.StringVar(&cfg.HostKey, "host-key", cfg.HostKey, "Path to server host private key")

	fs.StringVar(&cfg.MOTD, "motd", cfg.MOTD, "Message of the day displayed to connecting clients")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d: must be between 0 and 65535", cfg.Port)
	}

	return cfg, nil
}

// NewApp configures and initializes the peer registry and daemon server.
func NewApp(cfg *Config) (*App, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	reg := peer.NewRegistry()
	srv, err := daemon.NewServer(daemon.Config{
		Host:        cfg.Bind,
		Port:        cfg.Port,
		HostKeyPath: cfg.HostKey,
		Registry:    reg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize daemon server: %w", err)
	}

	return &App{
		Config:   cfg,
		Registry: reg,
		Server:   srv,
	}, nil
}

func main() {
	cfg, err := ParseConfig(os.Args[1:], os.Getenv)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		log.Fatalf("[shh] Configuration error: %v", err)
	}

	app, err := NewApp(cfg)
	if err != nil {
		log.Fatalf("[shh] Initialization error: %v", err)
	}

	// Capture interrupt and termination signals for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	if err := app.Server.Start(); err != nil {
		log.Fatalf("[shh] Failed to start daemon: %v", err)
	}

	log.Printf("[shh] Encrypted chat daemon listening on %s (log level: %s)...", app.Server.Addr(), cfg.LogLevel)
	if cfg.MOTD != "" {
		log.Printf("[shh] MOTD: %s", cfg.MOTD)
	}

	sig := <-stop
	log.Printf("[shh] Received %s, shutting down daemon gracefully...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := app.Server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[shh] Shutdown error: %v", err)
		os.Exit(1)
	}

	log.Println("[shh] Daemon stopped successfully.")
}
