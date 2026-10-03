package daemon_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"git.delikesance.cloud/delikesance/shh/internal/daemon"
	"git.delikesance.cloud/delikesance/shh/internal/peer"
	csh "github.com/charmbracelet/ssh"
	"golang.org/x/crypto/ssh"
)

// mockSSHContext implements csh.Context for unit testing the PublicKeyHandler hook.
type mockSSHContext struct {
	context.Context
	sync.Mutex
	user   string
	values map[interface{}]interface{}
}

func newMockSSHContext(user string) *mockSSHContext {
	return &mockSSHContext{
		Context: context.Background(),
		user:    user,
		values:  make(map[interface{}]interface{}),
	}
}

func (m *mockSSHContext) Lock()   { m.Mutex.Lock() }
func (m *mockSSHContext) Unlock() { m.Mutex.Unlock() }

func (m *mockSSHContext) User() string          { return m.user }
func (m *mockSSHContext) SessionID() string     { return "test-session-id" }
func (m *mockSSHContext) ClientVersion() string { return "SSH-2.0-TestClient" }
func (m *mockSSHContext) ServerVersion() string { return "SSH-2.0-shh" }
func (m *mockSSHContext) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *mockSSHContext) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
}
func (m *mockSSHContext) Permissions() *csh.Permissions {
	return &csh.Permissions{}
}
func (m *mockSSHContext) SetValue(key, value interface{}) {
	m.Lock()
	defer m.Unlock()
	m.values[key] = value
}
func (m *mockSSHContext) Value(key interface{}) interface{} {
	m.Lock()
	defer m.Unlock()
	if val, ok := m.values[key]; ok {
		return val
	}
	return m.Context.Value(key)
}

func TestNewServer_Config(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		srv, err := daemon.NewServer(daemon.Config{})
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}
		if srv == nil {
			t.Fatalf("expected non-nil server")
		}
		if srv.Registry() == nil {
			t.Errorf("expected non-nil default peer registry")
		}
	})

	t.Run("custom valid configuration", func(t *testing.T) {
		reg := peer.NewRegistry()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("failed to create signer: %v", err)
		}

		cfg := daemon.Config{
			Host:          "127.0.0.1",
			Port:          2222,
			HostKeySigner: signer,
			Registry:      reg,
			IdleTimeout:   10 * time.Second,
			MaxTimeout:    60 * time.Second,
			Version:       "shh-custom-v1",
		}

		srv, err := daemon.NewServer(cfg)
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}
		if srv.Registry() != reg {
			t.Errorf("expected registry to match configured registry")
		}
	})

	t.Run("invalid port numbers", func(t *testing.T) {
		invalidPorts := []int{-1, 65536, 70000}
		for _, port := range invalidPorts {
			_, err := daemon.NewServer(daemon.Config{Port: port})
			if err == nil {
				t.Errorf("expected error for invalid port %d, got nil", port)
			}
		}
	})
}

func TestPublicKeyAuth_HandlerHook(t *testing.T) {
	srv, err := daemon.NewServer(daemon.Config{})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}

	expectedFp := peer.FingerprintKey(sshPub)

	t.Run("valid ed25519 key with valid username", func(t *testing.T) {
		ctx := newMockSSHContext("alice")
		ok := srv.PublicKeyHandler(ctx, sshPub)
		if !ok {
			t.Fatalf("expected PublicKeyHandler to return true for valid ed25519 key")
		}

		// Verify public key in context
		storedKey := ctx.Value(daemon.ContextKeyPublicKey)
		if storedKey == nil {
			t.Errorf("expected %v to be set in context", daemon.ContextKeyPublicKey)
		}

		// Verify fingerprint in context
		storedFp, ok := ctx.Value(daemon.ContextKeyFingerprint).(string)
		if !ok || storedFp != expectedFp {
			t.Errorf("expected fingerprint %q in context, got %q", expectedFp, storedFp)
		}

		// Verify peer in context
		p, ok := ctx.Value(daemon.ContextKeyPeer).(*peer.Peer)
		if !ok || p == nil {
			t.Fatalf("expected *peer.Peer in context, got %T (%v)", ctx.Value(daemon.ContextKeyPeer), ctx.Value(daemon.ContextKeyPeer))
		}
		if p.Handle() != "alice" {
			t.Errorf("expected peer handle 'alice', got %q", p.Handle())
		}
		if p.Fingerprint() != expectedFp {
			t.Errorf("expected peer fingerprint %q, got %q", expectedFp, p.Fingerprint())
		}
	})

	t.Run("valid ed25519 key with empty username generates default handle", func(t *testing.T) {
		ctx := newMockSSHContext("")
		ok := srv.PublicKeyHandler(ctx, sshPub)
		if !ok {
			t.Fatalf("expected PublicKeyHandler to return true")
		}

		p, ok := ctx.Value(daemon.ContextKeyPeer).(*peer.Peer)
		if !ok || p == nil {
			t.Fatalf("expected *peer.Peer in context")
		}
		if err := peer.ValidateHandle(p.Handle()); err != nil {
			t.Errorf("expected generated handle to be valid, got %q: %v", p.Handle(), err)
		}
	})

	t.Run("nil public key is rejected", func(t *testing.T) {
		ctx := newMockSSHContext("bob")
		ok := srv.PublicKeyHandler(ctx, nil)
		if ok {
			t.Errorf("expected PublicKeyHandler to return false for nil key")
		}
	})

	t.Run("unsupported key type (RSA) is rejected", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate rsa key: %v", err)
		}
		rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to create rsa ssh public key: %v", err)
		}

		ctx := newMockSSHContext("charlie")
		ok := srv.PublicKeyHandler(ctx, rsaPub)
		if ok {
			t.Errorf("expected PublicKeyHandler to reject RSA key (only Ed25519 supported for E2EE)")
		}
	})

	t.Run("duplicate claimed handle falls back to fingerprint handle", func(t *testing.T) {
		// Register alice first with key1
		p1, err := peer.NewPeer(sshPub, "alice")
		if err != nil {
			t.Fatalf("failed to create peer: %v", err)
		}
		if err := srv.Registry().Register(p1); err != nil {
			t.Fatalf("failed to register peer: %v", err)
		}
		defer func() {
			_ = srv.Registry().Unregister(p1.Fingerprint())
		}()

		// Another user with key2 tries to connect as "alice"
		pub2, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		sshPub2, err := ssh.NewPublicKey(pub2)
		if err != nil {
			t.Fatalf("failed to create ssh public key: %v", err)
		}
		fp2 := peer.FingerprintKey(sshPub2)

		ctx2 := newMockSSHContext("alice")
		ok := srv.PublicKeyHandler(ctx2, sshPub2)
		if !ok {
			t.Fatalf("expected PublicKeyHandler to succeed with fallback handle")
		}

		p2, ok := ctx2.Value(daemon.ContextKeyPeer).(*peer.Peer)
		if !ok || p2 == nil {
			t.Fatalf("expected *peer.Peer in context")
		}
		expectedFallback := "u_" + fp2[:8]
		if p2.Handle() != expectedFallback {
			t.Errorf("expected fallback handle %q, got %q", expectedFallback, p2.Handle())
		}
	})

	t.Run("re-authenticating same key with existing handle is allowed", func(t *testing.T) {
		// Register alice with sshPub
		p, err := peer.NewPeer(sshPub, "alice")
		if err != nil {
			t.Fatalf("failed to create peer: %v", err)
		}
		if err := srv.Registry().Register(p); err != nil {
			t.Fatalf("failed to register peer: %v", err)
		}
		defer func() {
			_ = srv.Registry().Unregister(p.Fingerprint())
		}()

		// Same key authenticates again as "alice"
		ctx := newMockSSHContext("alice")
		ok := srv.PublicKeyHandler(ctx, sshPub)
		if !ok {
			t.Fatalf("expected PublicKeyHandler to return true")
		}
		pAuth, ok := ctx.Value(daemon.ContextKeyPeer).(*peer.Peer)
		if !ok || pAuth == nil {
			t.Fatalf("expected *peer.Peer in context")
		}
		if pAuth.Handle() != "alice" {
			t.Errorf("expected handle 'alice' to be preserved for same key, got %q", pAuth.Handle())
		}
	})
}

func TestServer_GracefulShutdown(t *testing.T) {
	srv, err := daemon.NewServer(daemon.Config{
		Host: "127.0.0.1",
		Port: 0, // OS assigned ephemeral port
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Start server
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	addr := srv.Addr()
	if addr == nil {
		t.Fatalf("expected non-nil server address after Start()")
	}

	// Verify server is listening
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to started server: %v", err)
	}
	_ = conn.Close()

	// Shutdown server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("graceful shutdown failed: %v", err)
	}

	// Verify listener is closed
	_, err = net.DialTimeout("tcp", addr.String(), 200*time.Millisecond)
	if err == nil {
		t.Fatalf("expected dial to fail after server shutdown")
	}
}

func TestServer_StartAlreadyStarted(t *testing.T) {
	srv, err := daemon.NewServer(daemon.Config{Host: "127.0.0.1", Port: 0})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	err = srv.Start()
	if !errors.Is(err, daemon.ErrServerAlreadyStarted) {
		t.Fatalf("expected ErrServerAlreadyStarted, got %v", err)
	}
}

func TestServer_Close(t *testing.T) {
	srv, err := daemon.NewServer(daemon.Config{Host: "127.0.0.1", Port: 0})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	// Close on unstarted server is a no-op
	if err := srv.Close(); err != nil {
		t.Errorf("expected nil error closing unstarted server, got %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	addr := srv.Addr().String()

	if err := srv.Close(); err != nil {
		t.Fatalf("failed to close running server: %v", err)
	}

	_, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		t.Fatalf("expected dial to fail after server Close()")
	}
}

func TestServer_ShutdownNotStarted(t *testing.T) {
	srv, err := daemon.NewServer(daemon.Config{Host: "127.0.0.1", Port: 0})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("expected nil error shutting down unstarted server, got %v", err)
	}
}

func TestNewServer_EphemeralHostKey(t *testing.T) {
	// Empty HostKeyPath and nil HostKeySigner generates in-memory ephemeral key
	srv, err := daemon.NewServer(daemon.Config{
		Host: "127.0.0.1",
		Port: 0,
	})
	if err != nil {
		t.Fatalf("failed to create server with ephemeral host key: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}
}

func TestServer_SSHClientIntegration(t *testing.T) {
	srv, err := daemon.NewServer(daemon.Config{
		Host: "127.0.0.1",
		Port: 0,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	addr := srv.Addr().String()

	// Client with valid Ed25519 key
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("failed to create client signer: %v", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            "testpeer",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	clientConn, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("failed to connect with valid ed25519 public key auth: %v", err)
	}
	defer clientConn.Close()

	// Verify session lifecycle: peer registration and teardown in Registry
	session, err := clientConn.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO: 0,
	}
	if err := session.RequestPty("xterm", 80, 24, modes); err != nil {
		t.Fatalf("failed to request pty: %v", err)
	}

	if err := session.Shell(); err != nil {
		t.Fatalf("failed to start shell: %v", err)
	}

	// Verify client is registered in registry
	clientFp := peer.FingerprintKey(clientSigner.PublicKey())
	var registeredPeer *peer.Peer
	for i := 0; i < 50; i++ {
		p, exists := srv.Registry().Get(clientFp)
		if exists && p != nil {
			registeredPeer = p
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if registeredPeer == nil {
		t.Fatalf("expected peer to be registered in server registry during active session")
	}
	if registeredPeer.Handle() != "testpeer" {
		t.Errorf("expected registered handle 'testpeer', got %q", registeredPeer.Handle())
	}

	// Close session & connection and verify unregistration
	_ = session.Close()
	_ = clientConn.Close()

	var unregistered bool
	for i := 0; i < 50; i++ {
		if _, exists := srv.Registry().Get(clientFp); !exists {
			unregistered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !unregistered {
		t.Errorf("expected peer to be unregistered after session close")
	}

	// Client with password auth (should be rejected as only public key is supported)
	badConfig := &ssh.ClientConfig{
		User:            "testpeer",
		Auth:            []ssh.AuthMethod{ssh.Password("somepassword")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Second,
	}

	_, err = ssh.Dial("tcp", addr, badConfig)
	if err == nil {
		t.Fatalf("expected dial with password auth to fail, but it succeeded")
	}
}

func TestServer_MultiSessionRosterSync(t *testing.T) {
	srv, err := daemon.NewServer(daemon.Config{
		Host: "127.0.0.1",
		Port: 0,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Close()

	addr := srv.Addr().String()

	// Alice client
	_, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	aliceSigner, _ := ssh.NewSignerFromKey(alicePriv)
	aliceConfig := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(aliceSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	aliceConn, err := ssh.Dial("tcp", addr, aliceConfig)
	if err != nil {
		t.Fatalf("failed to connect Alice: %v", err)
	}
	defer aliceConn.Close()

	aliceSession, err := aliceConn.NewSession()
	if err != nil {
		t.Fatalf("failed to open Alice session: %v", err)
	}
	defer aliceSession.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0}
	_ = aliceSession.RequestPty("xterm", 80, 24, modes)
	_ = aliceSession.Shell()

	// Wait for Alice session to register
	aliceFP := peer.FingerprintKey(aliceSigner.PublicKey())
	for i := 0; i < 50; i++ {
		if srv.ActiveSessions() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ActiveSessions() != 1 {
		t.Fatalf("expected 1 active session for Alice, got %d", srv.ActiveSessions())
	}

	// Bob client
	_, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	bobSigner, _ := ssh.NewSignerFromKey(bobPriv)
	bobConfig := &ssh.ClientConfig{
		User:            "bob",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(bobSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	bobConn, err := ssh.Dial("tcp", addr, bobConfig)
	if err != nil {
		t.Fatalf("failed to connect Bob: %v", err)
	}
	defer bobConn.Close()

	bobSession, err := bobConn.NewSession()
	if err != nil {
		t.Fatalf("failed to open Bob session: %v", err)
	}
	defer bobSession.Close()

	_ = bobSession.RequestPty("xterm", 80, 24, modes)
	_ = bobSession.Shell()

	// Wait for Bob session to register
	bobFP := peer.FingerprintKey(bobSigner.PublicKey())
	for i := 0; i < 50; i++ {
		if srv.ActiveSessions() == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ActiveSessions() != 2 {
		t.Fatalf("expected 2 active sessions for Alice & Bob, got %d", srv.ActiveSessions())
	}

	// Verify both peers in Registry
	if _, ok := srv.Registry().Get(aliceFP); !ok {
		t.Errorf("Alice missing from registry")
	}
	if _, ok := srv.Registry().Get(bobFP); !ok {
		t.Errorf("Bob missing from registry")
	}

	// Test SendTo and Broadcast
	sent := srv.SendTo(aliceFP, "test message")
	if !sent {
		t.Errorf("expected SendTo aliceFP to return true")
	}
	srv.Broadcast("broadcast message")

	// Disconnect Bob and verify session count drops to 1
	_ = bobSession.Close()
	_ = bobConn.Close()

	for i := 0; i < 50; i++ {
		if srv.ActiveSessions() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ActiveSessions() != 1 {
		t.Errorf("expected 1 active session after Bob left, got %d", srv.ActiveSessions())
	}

	// Disconnect Alice and verify session count drops to 0
	_ = aliceSession.Close()
	_ = aliceConn.Close()

	for i := 0; i < 50; i++ {
		if srv.ActiveSessions() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ActiveSessions() != 0 {
		t.Errorf("expected 0 active sessions after Alice left, got %d", srv.ActiveSessions())
	}
}


