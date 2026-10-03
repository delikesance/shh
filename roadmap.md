# Project Roadmap: `shh`

> **Real-time Status**:
> - **Current Milestone**: All Phases 1–6 Completed & Audited [APPROVED]
> - **Audit Status**: 100% Tests Pass, Zero Data Races, Zero CGO, Clean Signal Shutdown
> - **Next Up**: Final release ready

---

## Phase 1: Cryptographic Primitives & Ephemeral Memory (`internal/crypto`)
- [x] Ephemeral memory zeroization helper (`memclr`) with unit tests
- [x] Identity Fingerprinting (`SHA256(ssh.MarshalAuthorizedKey(pubKey))`)
- [x] Birational Curve Conversion (Ed25519 Edwards coordinates to Montgomery X25519 $u$-coordinates via `filippo.io/edwards25519`)
- [x] Diffie-Hellman Key Exchange using `crypto/ecdh`
- [x] Channel Key Derivation Function (HKDF-SHA256 RFC 5869 extract & expand)
- [x] ChaCha20-Poly1305 AEAD authenticated payload encryption with 96-bit monotonic sequence nonces

---

## Phase 2: Peer Identity & Registry (`internal/peer`)
- [x] Cryptographic peer identity representation bound to public key fingerprint
- [x] Thread-safe in-memory peer roster (`sync.RWMutex`)
- [x] Peer presence lifecycle tracking (online, active, idle, disconnect)
- [x] Nickname reservation, validation, and collision management

---

## Phase 3: Ephemeral Channel & Message Backlog (`internal/channel`)
- [x] Ephemeral in-memory ring-buffer for message frames (zero disk persistence)
- [x] Monotonic frame sequence tracking and replay protection
- [x] Direct message payload sealing and unsealing integration with `internal/crypto`
- [x] Secure channel teardown and explicit memory zeroization of shared keys and buffers

---

## Phase 4: SSH Daemon Infrastructure (`internal/daemon`)
- [x] Wish SSH listener configuration and PTY router setup (`github.com/charmbracelet/wish`)
- [x] RFC 4252 public-key authentication hook extracting client public key
- [x] Host key handling (loading or auto-generating Ed25519 host key)
- [x] Graceful connection termination and session lifecycle management

---

## Phase 5: Terminal User Interface (`internal/ui`)
- [x] Bubble Tea model and event loop architecture (`github.com/charmbracelet/bubbletea`)
- [x] Dual-pane responsive layout with Lipgloss (Peers list, DM conversation viewport, Input bar)
- [x] Keyboard navigation (`Tab`, `Shift-Tab`, arrows / `j`/`k`, `Enter`, `Esc`, `Ctrl+L`)
- [x] Slash command parsing and handlers (`/nick`, `/whois`, `/keys`, `/clear`, `/quit`)
- [x] Cipher badge and fingerprint status indicators

---

## Phase 6: System Integration & CLI Wiring (`cmd/shh`)
- [x] Integrate CLI flags (`-b`, `-p`, `-k`, `--motd`, `--log-level`) and environment variables
- [x] Connect Wish daemon sessions to Bubble Tea UI instances
- [x] End-to-end loopback integration tests (two SSH clients communicating in real time)
- [x] Memory hygiene audit ensuring zero secrets in memory after disconnect
