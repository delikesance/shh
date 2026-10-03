package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"testing"
	"time"

	"git.delikesance.cloud/delikesance/shh/internal/channel"
	"git.delikesance.cloud/delikesance/shh/internal/crypto"
	"git.delikesance.cloud/delikesance/shh/internal/peer"
	"golang.org/x/crypto/ssh"
)

func TestCLI_FlagsAndEnv(t *testing.T) {
	t.Run("default configuration without args or env", func(t *testing.T) {
		emptyEnv := func(key string) string { return "" }
		cfg, err := ParseConfig([]string{}, emptyEnv)
		if err != nil {
			t.Fatalf("unexpected error parsing default config: %v", err)
		}
		if cfg.Bind != "0.0.0.0" {
			t.Errorf("expected default bind '0.0.0.0', got %q", cfg.Bind)
		}
		if cfg.Port != 2222 {
			t.Errorf("expected default port 2222, got %d", cfg.Port)
		}
		if cfg.HostKey != ".ssh_host_key" {
			t.Errorf("expected default host-key '.ssh_host_key', got %q", cfg.HostKey)
		}
		if cfg.MOTD != "" {
			t.Errorf("expected default motd empty, got %q", cfg.MOTD)
		}
		if cfg.LogLevel != "info" {
			t.Errorf("expected default log-level 'info', got %q", cfg.LogLevel)
		}
	})

	t.Run("environment variables fallback", func(t *testing.T) {
		env := map[string]string{
			"SHH_BIND":      "127.0.0.1",
			"SHH_PORT":      "4444",
			"SHH_HOST_KEY":  "/etc/shh/custom_host_key",
			"SHH_MOTD":      "Welcome to SHH Test",
			"SHH_LOG_LEVEL": "debug",
		}
		getenv := func(key string) string { return env[key] }

		cfg, err := ParseConfig([]string{}, getenv)
		if err != nil {
			t.Fatalf("unexpected error parsing env config: %v", err)
		}
		if cfg.Bind != "127.0.0.1" {
			t.Errorf("expected bind '127.0.0.1', got %q", cfg.Bind)
		}
		if cfg.Port != 4444 {
			t.Errorf("expected port 4444, got %d", cfg.Port)
		}
		if cfg.HostKey != "/etc/shh/custom_host_key" {
			t.Errorf("expected host-key '/etc/shh/custom_host_key', got %q", cfg.HostKey)
		}
		if cfg.MOTD != "Welcome to SHH Test" {
			t.Errorf("expected motd 'Welcome to SHH Test', got %q", cfg.MOTD)
		}
		if cfg.LogLevel != "debug" {
			t.Errorf("expected log-level 'debug', got %q", cfg.LogLevel)
		}
	})

	t.Run("CLI flags override environment variables", func(t *testing.T) {
		env := map[string]string{
			"SHH_BIND":      "127.0.0.1",
			"SHH_PORT":      "4444",
			"SHH_HOST_KEY":  "/etc/shh/custom_host_key",
			"SHH_MOTD":      "Env MOTD",
			"SHH_LOG_LEVEL": "debug",
		}
		getenv := func(key string) string { return env[key] }

		args := []string{
			"-b", "10.0.0.1",
			"-p", "5555",
			"-k", "./my_key",
			"--motd", "CLI Overridden MOTD",
			"--log-level", "warn",
		}

		cfg, err := ParseConfig(args, getenv)
		if err != nil {
			t.Fatalf("unexpected error parsing overridden config: %v", err)
		}
		if cfg.Bind != "10.0.0.1" {
			t.Errorf("expected bind '10.0.0.1', got %q", cfg.Bind)
		}
		if cfg.Port != 5555 {
			t.Errorf("expected port 5555, got %d", cfg.Port)
		}
		if cfg.HostKey != "./my_key" {
			t.Errorf("expected host-key './my_key', got %q", cfg.HostKey)
		}
		if cfg.MOTD != "CLI Overridden MOTD" {
			t.Errorf("expected motd 'CLI Overridden MOTD', got %q", cfg.MOTD)
		}
		if cfg.LogLevel != "warn" {
			t.Errorf("expected log-level 'warn', got %q", cfg.LogLevel)
		}
	})

	t.Run("long format CLI flags support", func(t *testing.T) {
		emptyEnv := func(key string) string { return "" }
		args := []string{
			"--bind", "192.168.1.50",
			"--port", "6666",
			"--host-key", "/tmp/host_key",
		}

		cfg, err := ParseConfig(args, emptyEnv)
		if err != nil {
			t.Fatalf("unexpected error parsing long flags: %v", err)
		}
		if cfg.Bind != "192.168.1.50" {
			t.Errorf("expected bind '192.168.1.50', got %q", cfg.Bind)
		}
		if cfg.Port != 6666 {
			t.Errorf("expected port 6666, got %d", cfg.Port)
		}
		if cfg.HostKey != "/tmp/host_key" {
			t.Errorf("expected host-key '/tmp/host_key', got %q", cfg.HostKey)
		}
	})

	t.Run("invalid environment port returns error", func(t *testing.T) {
		env := map[string]string{"SHH_PORT": "invalid-port"}
		getenv := func(key string) string { return env[key] }

		_, err := ParseConfig([]string{}, getenv)
		if err == nil {
			t.Fatalf("expected error for non-numeric SHH_PORT, got nil")
		}
	})

	t.Run("out of range port returns error", func(t *testing.T) {
		emptyEnv := func(key string) string { return "" }
		invalidPorts := []string{"-1", "65536", "99999"}
		for _, port := range invalidPorts {
			_, err := ParseConfig([]string{"-p", port}, emptyEnv)
			if err == nil {
				t.Errorf("expected error for out-of-range port %s, got nil", port)
			}
		}
	})

	t.Run("help flag returns flag.ErrHelp", func(t *testing.T) {
		emptyEnv := func(key string) string { return "" }
		_, err := ParseConfig([]string{"--help"}, emptyEnv)
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("expected flag.ErrHelp, got %v", err)
		}
	})
}

func TestEndToEnd_LoopbackChat(t *testing.T) {
	// 1. Spawn daemon on 127.0.0.1:0 (ephemeral port)
	cfg := &Config{
		Bind:     "127.0.0.1",
		Port:     0,
		HostKey:  "", // in-memory ephemeral host key
		MOTD:     "Welcome to shh loopback test",
		LogLevel: "debug",
	}

	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("failed to initialize application: %v", err)
	}

	if err := app.Server.Start(); err != nil {
		t.Fatalf("failed to start daemon server: %v", err)
	}

	// Ensure graceful shutdown on test conclusion
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = app.Server.Shutdown(shutdownCtx)
	}()

	addr := app.Server.Addr().String()
	if addr == "" {
		t.Fatalf("expected non-empty server address")
	}

	// 2. Generate Client Alice (Ed25519 SSH keypair) and dial daemon
	alicePub, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice keypair: %v", err)
	}
	aliceSigner, err := ssh.NewSignerFromKey(alicePriv)
	if err != nil {
		t.Fatalf("failed to create Alice signer: %v", err)
	}

	aliceConfig := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(aliceSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	aliceConn, err := ssh.Dial("tcp", addr, aliceConfig)
	if err != nil {
		t.Fatalf("Alice failed to connect to daemon: %v", err)
	}
	defer aliceConn.Close()

	aliceSession, err := aliceConn.NewSession()
	if err != nil {
		t.Fatalf("Alice failed to create SSH session: %v", err)
	}
	defer aliceSession.Close()

	termModes := ssh.TerminalModes{ssh.ECHO: 0}
	if err := aliceSession.RequestPty("xterm", 80, 24, termModes); err != nil {
		t.Fatalf("Alice failed to request PTY: %v", err)
	}
	if err := aliceSession.Shell(); err != nil {
		t.Fatalf("Alice failed to start shell: %v", err)
	}

	// 3. Generate Client Bob (Ed25519 SSH keypair) and dial daemon
	bobPub, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob keypair: %v", err)
	}
	bobSigner, err := ssh.NewSignerFromKey(bobPriv)
	if err != nil {
		t.Fatalf("failed to create Bob signer: %v", err)
	}

	bobConfig := &ssh.ClientConfig{
		User:            "bob",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(bobSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	bobConn, err := ssh.Dial("tcp", addr, bobConfig)
	if err != nil {
		t.Fatalf("Bob failed to connect to daemon: %v", err)
	}
	defer bobConn.Close()

	bobSession, err := bobConn.NewSession()
	if err != nil {
		t.Fatalf("Bob failed to create SSH session: %v", err)
	}
	defer bobSession.Close()

	if err := bobSession.RequestPty("xterm", 80, 24, termModes); err != nil {
		t.Fatalf("Bob failed to request PTY: %v", err)
	}
	if err := bobSession.Shell(); err != nil {
		t.Fatalf("Bob failed to start shell: %v", err)
	}

	// 4. Verifies both peers authenticate and appear in peer.Registry
	aliceFP := peer.FingerprintKey(aliceSigner.PublicKey())
	bobFP := peer.FingerprintKey(bobSigner.PublicKey())

	var alicePeer, bobPeer *peer.Peer
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pA, okA := app.Registry.Get(aliceFP)
		pB, okB := app.Registry.Get(bobFP)
		if okA && okB {
			alicePeer = pA
			bobPeer = pB
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if alicePeer == nil {
		t.Fatalf("Alice peer was not found in registry within deadline")
	}
	if bobPeer == nil {
		t.Fatalf("Bob peer was not found in registry within deadline")
	}

	if alicePeer.Handle() != "alice" {
		t.Errorf("expected Alice handle 'alice', got %q", alicePeer.Handle())
	}
	if bobPeer.Handle() != "bob" {
		t.Errorf("expected Bob handle 'bob', got %q", bobPeer.Handle())
	}
	if alicePeer.Presence() != peer.PresenceOnline {
		t.Errorf("expected Alice presence 'online', got %q", alicePeer.Presence())
	}
	if bobPeer.Presence() != peer.PresenceOnline {
		t.Errorf("expected Bob presence 'online', got %q", bobPeer.Presence())
	}
	if app.Registry.Count() != 2 {
		t.Errorf("expected registry peer count 2, got %d", app.Registry.Count())
	}

	// 5. Tests direct messaging between Alice and Bob over ephemeral channel (internal/channel)
	// Alice derives shared secret using Bob's public key
	aliceX25519Priv, err := crypto.Ed25519PrivateKeyToX25519(alicePriv)
	if err != nil {
		t.Fatalf("failed to convert Alice private key to X25519: %v", err)
	}
	bobRawPub := bobPeer.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if !bytes.Equal(bobPub, bobRawPub) {
		t.Fatalf("Bob public key in registry does not match generated key")
	}
	bobX25519Pub, err := crypto.Ed25519PublicKeyToX25519(bobRawPub)
	if err != nil {
		t.Fatalf("failed to convert Bob public key to X25519: %v", err)
	}
	aliceSharedSecret, err := crypto.ComputeSharedSecret(aliceX25519Priv, bobX25519Pub)
	if err != nil {
		t.Fatalf("Alice failed to compute shared secret: %v", err)
	}

	// Bob derives shared secret using Alice's public key
	bobX25519Priv, err := crypto.Ed25519PrivateKeyToX25519(bobPriv)
	if err != nil {
		t.Fatalf("failed to convert Bob private key to X25519: %v", err)
	}
	aliceRawPub := alicePeer.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if !bytes.Equal(alicePub, aliceRawPub) {
		t.Fatalf("Alice public key in registry does not match generated key")
	}
	aliceX25519Pub, err := crypto.Ed25519PublicKeyToX25519(aliceRawPub)
	if err != nil {
		t.Fatalf("failed to convert Alice public key to X25519: %v", err)
	}
	bobSharedSecret, err := crypto.ComputeSharedSecret(bobX25519Priv, aliceX25519Pub)
	if err != nil {
		t.Fatalf("Bob failed to compute shared secret: %v", err)
	}

	// Verify ECDH agreement
	if !bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		t.Fatalf("shared secrets between Alice and Bob do not match")
	}

	// Derive symmetric channel keys (HKDF-SHA256)
	salt := []byte("shh-e2e-loopback-salt")
	info := "shh-dm-chacha20-poly1305"
	aliceChannelKey, err := crypto.DeriveChannelKey(aliceSharedSecret, salt, info)
	if err != nil {
		t.Fatalf("Alice failed to derive channel key: %v", err)
	}
	bobChannelKey, err := crypto.DeriveChannelKey(bobSharedSecret, salt, info)
	if err != nil {
		t.Fatalf("Bob failed to derive channel key: %v", err)
	}

	if !bytes.Equal(aliceChannelKey, bobChannelKey) {
		t.Fatalf("derived channel keys do not match")
	}

	// Establish ephemeral channels
	aliceChannel := channel.NewChannel(aliceFP, bobFP, aliceChannelKey)
	bobChannel := channel.NewChannel(bobFP, aliceFP, bobChannelKey)

	// Alice sends message to Bob
	plaintext1 := []byte("Hello Bob, this is an end-to-end encrypted direct message!")
	nonce1, ciphertext1, err := aliceChannel.Seal(plaintext1)
	if err != nil {
		t.Fatalf("Alice Seal failed: %v", err)
	}

	// Bob decrypts Alice's message
	decrypted1, err := bobChannel.Open(nonce1, ciphertext1)
	if err != nil {
		t.Fatalf("Bob Open failed: %v", err)
	}
	if !bytes.Equal(decrypted1, plaintext1) {
		t.Fatalf("decrypted message %q does not match original %q", decrypted1, plaintext1)
	}

	// Store message in Bob's channel buffer
	m1 := &channel.Message{
		ID:          "msg-001",
		Seq:         1,
		SenderFP:    aliceFP,
		RecipientFP: bobFP,
		Content:     decrypted1,
		Timestamp:   time.Now(),
	}
	bobChannel.Push(m1)
	if len(bobChannel.Messages()) != 1 {
		t.Errorf("expected Bob channel buffer len 1, got %d", len(bobChannel.Messages()))
	}

	// Bob sends response to Alice
	plaintext2 := []byte("Hello Alice! Cryptographic handshake verified.")
	nonce2, ciphertext2, err := bobChannel.Seal(plaintext2)
	if err != nil {
		t.Fatalf("Bob Seal failed: %v", err)
	}

	// Alice decrypts Bob's message
	decrypted2, err := aliceChannel.Open(nonce2, ciphertext2)
	if err != nil {
		t.Fatalf("Alice Open failed: %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext2) {
		t.Fatalf("decrypted response %q does not match original %q", decrypted2, plaintext2)
	}

	// Store message in Alice's channel buffer
	m2 := &channel.Message{
		ID:          "msg-002",
		Seq:         1,
		SenderFP:    bobFP,
		RecipientFP: aliceFP,
		Content:     decrypted2,
		Timestamp:   time.Now(),
	}
	aliceChannel.Push(m2)
	if len(aliceChannel.Messages()) != 1 {
		t.Errorf("expected Alice channel buffer len 1, got %d", len(aliceChannel.Messages()))
	}

	// Verify replay rejection
	_, err = bobChannel.Open(nonce1, ciphertext1)
	if err == nil {
		t.Errorf("expected replay of nonce1 to fail Open, but succeeded")
	}

	// 6. Tests disconnect of clients and verifies peer cleanup in registry and memory scrubbing
	// Disconnect Bob
	if err := bobSession.Close(); err != nil {
		t.Logf("Bob session close error (non-fatal): %v", err)
	}
	_ = bobConn.Close()

	// Disconnect Alice
	if err := aliceSession.Close(); err != nil {
		t.Logf("Alice session close error (non-fatal): %v", err)
	}
	_ = aliceConn.Close()

	// Verify unregistration from peer.Registry
	unregistered := false
	cleanupDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(cleanupDeadline) {
		if app.Registry.Count() == 0 {
			unregistered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !unregistered {
		t.Fatalf("peers were not cleaned up from registry after disconnect, remaining count: %d", app.Registry.Count())
	}

	if _, exists := app.Registry.Get(aliceFP); exists {
		t.Errorf("Alice still found in registry after disconnect")
	}
	if _, exists := app.Registry.Get(bobFP); exists {
		t.Errorf("Bob still found in registry after disconnect")
	}

	// Close channels and verify channel memory scrubbing
	aliceChannel.Close()
	bobChannel.Close()

	if !aliceChannel.IsClosed() || !bobChannel.IsClosed() {
		t.Errorf("expected both channels to be marked closed")
	}
	if len(aliceChannel.Messages()) != 0 {
		t.Errorf("expected Alice buffer to be empty after Close(), got %d", len(aliceChannel.Messages()))
	}
	if len(bobChannel.Messages()) != 0 {
		t.Errorf("expected Bob buffer to be empty after Close(), got %d", len(bobChannel.Messages()))
	}
	for i, b := range aliceChannel.SharedKey() {
		if b != 0 {
			t.Errorf("aliceChannel shared key byte %d was not zeroed: %d", i, b)
		}
	}
	for i, b := range bobChannel.SharedKey() {
		if b != 0 {
			t.Errorf("bobChannel shared key byte %d was not zeroed: %d", i, b)
		}
	}

	// Scrub remaining intermediate secret buffers
	crypto.Memclr(aliceX25519Priv)
	crypto.Memclr(bobX25519Priv)
	crypto.Memclr(aliceSharedSecret)
	crypto.Memclr(bobSharedSecret)

	for i, b := range aliceX25519Priv {
		if b != 0 {
			t.Errorf("aliceX25519Priv byte %d not scrubbed", i)
		}
	}
	for i, b := range bobX25519Priv {
		if b != 0 {
			t.Errorf("bobX25519Priv byte %d not scrubbed", i)
		}
	}
	for i, b := range aliceSharedSecret {
		if b != 0 {
			t.Errorf("aliceSharedSecret byte %d not scrubbed", i)
		}
	}
	for i, b := range bobSharedSecret {
		if b != 0 {
			t.Errorf("bobSharedSecret byte %d not scrubbed", i)
		}
	}
}
