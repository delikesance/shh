SHH(1)                      General Commands Manual                     SHH(1)

NAME
     shh – peer-to-peer encrypted terminal direct messaging over SSH with
     client key derivation

SYNOPSIS
     ssh [-p port] [-i identity_file] [nickname@]chat.delikesance.cloud
     shh [server] [-b address] [-p port] [-k host_key] [--log-level level]

DESCRIPTION
     shh is an ephemeral, zero-install terminal direct-messaging daemon built
     on top of the SSH protocol. It allows connected peers to discover one
     another in real-time and engage in end-to-end encrypted direct-message
     (DM) conversations using only a standard OpenSSH client (ssh(1)).

     Authentication is entirely cryptographic: during the initial SSH transport
     handshake, each client's identity is pinned to their SSH public key
     (e.g., ssh-ed25519 or ssh-rsa). Handles and session states are bound to
     public key fingerprints, rendering handle hijacking and impersonation
     cryptographically impossible.

     When two peers establish a private direct message channel, shh computes
     a shared symmetric channel key derived from both clients' cryptographic
     credentials using Montgomery-curve Diffie-Hellman (X25519) and HKDF-SHA256.
     Message frames are sealed in-flight using authenticated encryption
     (ChaCha20-Poly1305 AEAD).

     All conversation logs and key materials are held strictly in volatile
     system memory (RAM) with ephemeral ring-buffer semantics. Nothing is ever
     persisted to secondary storage.

TERMINAL UI & INTERACTIVE NAVIGATION
     Upon connecting, shh renders a dual-pane terminal interface:

     ┌─ Online Peers (3) ───────┬─ DM: @bob [SHA256:8f2a...c4e1] ──────────────────┐
     │ ● @alice (you)           │ [01:24:02] @bob: yo, got the new keypair?        │
     │ ● @bob [active]          │ [01:24:18] @alice: derived via X25519, looks rad │
     │ ○ @charlie [idle]        │                                                  │
     │                          │ 🔒 Cipher: ChaCha20-Poly1305 (Ephemeral X25519)  │
     ├──────────────────────────┴──────────────────────────────────────────────────┤
     │ > Type your message...                                                      │
     └─────────────────────────────────────────────────────────────────────────────┘

   KEYBOARD CONTROLS
     Tab / Shift-Tab
             Cycle active focus between the peer list, the message viewport,
             and the text input line.

     Up / Down, j / k
             Navigate through the list of online peers or scroll through
             the conversation backlog.

     Enter   Initiate or open a direct message channel with the selected peer,
             or dispatch the message currently in the input buffer.

     Esc     Dismiss current DM channel, clear input buffer, or return
             focus to the peer roster.

     Ctrl+L  Force a full terminal screen redraw (SIGWINCH / repaint).

     Ctrl+C, Ctrl+D
             Terminate the SSH session and immediately scrub ephemeral
             key buffers.

SLASH COMMANDS
     The following in-band commands may be dispatched directly from the input
     line:

     /nick <handle>
             Request a new display handle bound to your public key fingerprint.

     /whois <handle>
             Display a peer's public key algorithm, full SHA-256 fingerprint,
             connection uptime, and cipher suite parameters.

     /keys   Inspect the current active channel's derived symmetric keys,
             salt vectors, and frame sequence counters.

     /clear  Flush and purge the current channel backlog from memory.

     /quit   Disconnect cleanly from the daemon.

CRYPTOGRAPHY & KEY DERIVATION
     shh enforces a zero-trust cryptographic model designed for terminal-driven
     client environments:

     1. Identity & Public Key Pinning
        Clients present their public credentials during RFC 4252 publickey
        authentication. The daemon computes an invariant fingerprint:
              FP = SHA256(ssh.MarshalAuthorizedKey(client_pubkey))

     2. Birational Curve Conversion (Ed25519 to X25519)
        For modern Edwards-curve identities (ssh-ed25519), public keys are
        mapped to Montgomery coordinates (X25519) via birational equivalence:
              u = (1 + y) / (1 - y)  mod (2^255 - 19)

     3. Key Derivation Function (HKDF-SHA256)
        Channel encryption keys are extracted and expanded using RFC 5869:
              PRK   = HKDF-Extract(salt = session_salt, IKM = ECDH(kA, kB))
              K_enc = HKDF-Expand(PRK, info = "shh-dm-chacha20-poly1305", L = 32)

     4. Authenticated Payload Encryption (AEAD)
        Payload packets are authenticated and encrypted using ChaCha20-Poly1305
        (RFC 8439) with a 96-bit monotonic sequence counter nonce:
              ciphertext, tag = ChaCha20-Poly1305-Seal(K_enc, nonce, payload, AD)

     5. Ephemeral Memory Hygiene
        All decryption contexts, message ring-buffers, and intermediate key
        matrices reside solely in memory and are explicitly zeroed (memclr)
        upon channel closure or peer disconnection.

SERVER OPTIONS
     shh server accepts the following command-line flags:

     -b, --bind address
             IP address or hostname to bind the SSH listener to (default:
             0.0.0.0).

     -p, --port number
             Port number to listen for incoming SSH connections (default: 2222).

     -k, --host-key path
             Filesystem path to the server's Ed25519 private host key (default:
             ~/.ssh/shh_ed25519). If omitted and absent, a fresh host key is
             automatically minted.

     --motd string
             Custom banner or message of the day displayed in the top header.

     --log-level level
             Logging verbosity: debug, info, warn, or error (default: info).

ENVIRONMENT
     SHH_PORT
             Overrides the default port (2222) if not specified via -p.

     SHH_HOST_KEY
             Specifies the path to the daemon's private host key.

     SHH_BIND
             Specifies the network interface address to bind.

EXAMPLES
   Connecting as a Client
     Connect using the default local SSH key (~/.ssh/id_ed25519):
           $ ssh -p 2222 chat.delikesance.cloud

     Connect with a preferred handle and specific identity file:
           $ ssh -p 2222 -i ~/.ssh/id_delikesance angelo@chat.delikesance.cloud

   Running a Self-Hosted Node
     Build and start the daemon locally on port 2222:
           $ go run ./cmd/shh -p 2222

     Run via Docker with persistent host keys:
           $ docker run -d \
               --name shh-server \
               -p 2222:2222 \
               -v /etc/shh:/keys \
               delikesance/shh:latest

ARCHITECTURE & STACK
     shh is built from scratch in Go with zero bloated CGO dependencies:

     • charmbracelet/wish        SSH daemon engine & RFC-compliant PTY router
     • charmbracelet/bubbletea   Elm-architecture terminal UI event loop
     • charmbracelet/lipgloss    ANSI layout styling and responsive terminal grids
     • golang.org/x/crypto/ssh   Low-level SSH publickey negotiation
     • filippo.io/edwards25519   Strict RFC 8032 Edwards curve mathematics
     • crypto/ecdh               Hardware-accelerated Montgomery X25519 ECDH
     • golang.org/x/crypto/hkdf  RFC 5869 HMAC-based key derivation

DIAGNOSTICS
     shh exits 0 on graceful termination (SIGINT, SIGTERM) and >0 if the
     port cannot be bound or host key generation encounters an I/O fault.

AUTHORS
     Designed and created by Angelo Clauin <clauinangelo@proton.me>.

SEE ALSO
     ssh(1), ssh-keygen(1), sshd(8), RFC 4252, RFC 5869, RFC 8439
