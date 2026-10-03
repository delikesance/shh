package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"git.delikesance.cloud/delikesance/shh/internal/peer"
	"git.delikesance.cloud/delikesance/shh/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
	csh "github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	bmw "github.com/charmbracelet/wish/bubbletea"
	"golang.org/x/crypto/ssh"
)

// Context keys for session connection context values.
type contextKey string

const (
	ContextKeyPublicKey   contextKey = "shh-public-key"
	ContextKeyFingerprint contextKey = "shh-fingerprint"
	ContextKeyPeer        contextKey = "shh-peer"
)

var (
	ErrInvalidPort          = errors.New("invalid port number: must be between 0 and 65535")
	ErrServerAlreadyStarted = errors.New("server already started")
	ErrServerNotRunning     = errors.New("server is not running")
)

// Config holds the configuration options for the SSH chat daemon.
type Config struct {
	Host          string
	Port          int
	HostKeyPath   string
	HostKeySigner ssh.Signer
	Registry      *peer.Registry
	IdleTimeout   time.Duration
	MaxTimeout    time.Duration
	Version       string
}

// Server encapsulates the Wish SSH server, peer registry, and session lifecycle.
type Server struct {
	cfg        Config
	registry   *peer.Registry
	wishServer *csh.Server
	listener   net.Listener
	actualAddr net.Addr
	done       chan struct{}
	started    bool
	mu         sync.Mutex
}

// NewServer configures and initializes a new daemon Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, ErrInvalidPort
	}
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.Registry == nil {
		cfg.Registry = peer.NewRegistry()
	}

	// Resolve or generate host key signer
	if cfg.HostKeySigner == nil {
		if cfg.HostKeyPath != "" {
			signer, err := LoadOrGenerateHostKey(cfg.HostKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load host key: %w", err)
			}
			cfg.HostKeySigner = signer
		} else {
			// Generate ephemeral in-memory Ed25519 signer
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("failed to generate ephemeral host key: %w", err)
			}
			signer, err := ssh.NewSignerFromKey(priv)
			if err != nil {
				return nil, fmt.Errorf("failed to create signer from ephemeral key: %w", err)
			}
			cfg.HostKeySigner = signer
		}
	}

	srv := &Server{
		cfg:      cfg,
		registry: cfg.Registry,
	}

	// Host key option to inject pre-configured signer into wish server
	withSignerOption := func(s *csh.Server) error {
		s.AddHostKey(cfg.HostKeySigner)
		return nil
	}

	// Bubble Tea handler creating a new UI model per SSH session
	teaHandler := func(sess csh.Session) (tea.Model, []tea.ProgramOption) {
		p, _ := sess.Context().Value(ContextKeyPeer).(*peer.Peer)
		handle := "anonymous"
		fp := ""
		if p != nil {
			handle = p.Handle()
			fp = p.Fingerprint()
		} else if sess.PublicKey() != nil {
			fp = peer.FingerprintKey(sess.PublicKey())
			handle = sess.User()
		}
		m := ui.NewModel(handle, fp)
		return m, []tea.ProgramOption{tea.WithAltScreen()}
	}

	// Session middleware: handles peer registry registration and teardown lifecycle
	sessionMiddleware := func(next csh.Handler) csh.Handler {
		return func(sess csh.Session) {
			p, _ := sess.Context().Value(ContextKeyPeer).(*peer.Peer)
			if p != nil {
				if err := srv.registry.Register(p); errors.Is(err, peer.ErrDuplicateHandle) {
					fallback := "u_" + p.Fingerprint()[:8]
					if err := p.SetHandle(fallback); err == nil {
						_ = srv.registry.Register(p)
					}
				}
				defer func() {
					_ = srv.registry.Unregister(p.Fingerprint())
				}()
			}
			next(sess)
		}
	}

	opts := []csh.Option{
		wish.WithAddress(fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)),
		withSignerOption,
		wish.WithPublicKeyAuth(srv.PublicKeyHandler),
		wish.WithMiddleware(
			bmw.Middleware(teaHandler),
			sessionMiddleware,
		),
	}

	if cfg.IdleTimeout > 0 {
		opts = append(opts, wish.WithIdleTimeout(cfg.IdleTimeout))
	}
	if cfg.MaxTimeout > 0 {
		opts = append(opts, wish.WithMaxTimeout(cfg.MaxTimeout))
	}
	if cfg.Version != "" {
		opts = append(opts, wish.WithVersion(cfg.Version))
	}

	ws, err := wish.NewServer(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize wish server: %w", err)
	}

	srv.wishServer = ws
	return srv, nil
}

// PublicKeyHandler handles RFC 4252 public-key authentication:
// validates the key algorithm (strictly Ed25519 for E2EE curve conversion),
// calculates the invariant SHA-256 fingerprint, initializes the peer object,
// and binds the peer and identity keys to the SSH connection context.
func (s *Server) PublicKeyHandler(ctx csh.Context, key csh.PublicKey) bool {
	if key == nil {
		return false
	}

	// Validate key type: shh requires Ed25519 for Edwards-to-Montgomery curve conversion
	if key.Type() != ssh.KeyAlgoED25519 {
		return false
	}

	fp := peer.FingerprintKey(key)
	if fp == "" {
		return false
	}

	// Determine client handle: check user specified in ssh -p port handle@host
	handle := ctx.User()
	if err := peer.ValidateHandle(handle); err != nil {
		if len(fp) >= 8 {
			handle = "u_" + fp[:8]
		} else {
			handle = "anon"
		}
	} else if existing, exists := s.registry.GetByHandle(handle); exists && existing.Fingerprint() != fp {
		// Requested handle is already claimed by another peer; generate default handle bound to key fingerprint
		if len(fp) >= 8 {
			handle = "u_" + fp[:8]
		} else {
			handle = "anon"
		}
	}

	p, err := peer.NewPeer(key, handle)
	if err != nil {
		return false
	}

	ctx.SetValue(ContextKeyPeer, p)
	ctx.SetValue(ContextKeyFingerprint, fp)
	ctx.SetValue(ContextKeyPublicKey, key)

	return true
}

type readyListener struct {
	net.Listener
	readyOnce sync.Once
	ready     chan struct{}
}

func (r *readyListener) Accept() (net.Conn, error) {
	r.readyOnce.Do(func() {
		close(r.ready)
	})
	return r.Listener.Accept()
}

// Start binds to the configured network address and launches the Wish SSH accept loop in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return ErrServerAlreadyStarted
	}

	addr := s.wishServer.Addr
	if addr == "" {
		addr = ":2222"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	ready := make(chan struct{})
	rln := &readyListener{
		Listener: ln,
		ready:    ready,
	}

	s.listener = rln
	s.actualAddr = ln.Addr()
	s.started = true
	s.done = make(chan struct{})

	go func() {
		defer close(s.done)
		_ = s.wishServer.Serve(rln)
	}()

	select {
	case <-ready:
		return nil
	case <-s.done:
		s.started = false
		return errors.New("server terminated before ready")
	}
}

// Shutdown gracefully terminates the SSH server and all active connections within the provided context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	done := s.done
	s.mu.Unlock()

	err := s.wishServer.Shutdown(ctx)
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()

	return err
}

// Addr returns the current listening network address, or nil if not listening.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return s.actualAddr
}

// Registry returns the in-memory peer registry attached to the server.
func (s *Server) Registry() *peer.Registry {
	return s.registry
}

// Close immediately closes the SSH listener and active sessions.
func (s *Server) Close() error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = false
	if s.listener != nil {
		_ = s.listener.Close()
	}
	done := s.done
	s.mu.Unlock()

	err := s.wishServer.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	if done != nil {
		<-done
	}
	return err
}
