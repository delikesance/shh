# GEMINI.md - Project Context & Rules for `shh`

## 1. Project Overview

`shh` is an ephemeral, zero-install terminal direct-messaging daemon built on top of the SSH protocol. It allows connected peers to discover one another in real time and conduct end-to-end encrypted direct-message (DM) conversations using only standard OpenSSH clients (`ssh(1)`).

### Core Tenets
- **Zero-Install Client Access**: No client-side installations, binaries, or browser apps required. Users connect directly via `ssh -p 2222 [nickname@]host`.
- **Cryptographic Identity Pinning**: User handles and sessions are strictly pinned to their SSH public key fingerprints (`SHA256`). Handle impersonation and hijacking are cryptographically impossible.
- **End-to-End Encrypted DMs**: Shared channel keys are derived from client credentials using birational curve conversion (Ed25519 to X25519), Diffie-Hellman (ECDH), and HKDF-SHA256. Messages in flight are sealed with ChaCha20-Poly1305 AEAD.
- **Zero Persistence & Ephemeral Memory Hygiene**: All message history, peer rosters, and derived key material reside strictly in volatile system memory (RAM ring-buffers). Absolutely nothing is written to disk. Key buffers and cipher contexts are explicitly wiped on channel or session teardown.

---

## 2. Technology Stack & Constraints

- **Language**: Go (`go 1.26.8+`)
- **SSH Daemon Engine**: `github.com/charmbracelet/wish`, `golang.org/x/crypto/ssh`
- **Terminal UI**: `github.com/charmbracelet/bubbletea` (Elm architecture), `github.com/charmbracelet/lipgloss` (styling and responsive layouts)
- **Cryptography**:
  - `crypto/ecdh` (X25519 key exchange)
  - `filippo.io/edwards25519` (Edwards-curve arithmetic and birational conversion)
  - `golang.org/x/crypto/hkdf` (RFC 5869 key derivation)
  - `golang.org/x/crypto/chacha20poly1305` (RFC 8439 AEAD authenticated encryption)
- **Dependency Rule**: **Zero CGO dependencies**. All code must compile statically and cross-platform with pure Go.

---

## 3. Architecture & Directory Structure

When implementing components, follow this layout:

```text
.
├── cmd/
│   └── shh/                 # Daemon entrypoint, CLI flag parsing, signals
├── internal/
│   ├── crypto/              # Curve conversion (Ed25519 -> X25519), ECDH, HKDF, ChaCha20-Poly1305, memclr
│   ├── daemon/              # Wish/SSH listener, connection handling, public key extraction
│   ├── peer/                # Peer registry, public-key identity binding, presence, thread-safe roster
│   ├── channel/             # In-memory DM channels, monotonic nonces, ephemeral ring buffers
│   └── ui/                  # Bubble Tea models, views, keybindings, slash commands, Lipgloss styles
├── Makefile                 # Build, run, test targets
├── go.mod
├── README.md
├── roadmap.md
└── GEMINI.md
```

---

## 4. Cryptographic Specifications & Rules

1. **Identity Fingerprinting**:
   - Compute the invariant identity fingerprint during RFC 4252 publickey authentication:
     ```go
     fingerprint := sha256.Sum256(ssh.MarshalAuthorizedKey(clientPubKey))
     ```
   - All session state, peer mapping, and nick claims must be verified against this fingerprint.

2. **Curve Conversion (Ed25519 to Montgomery X25519)**:
   - For `ssh-ed25519` identities, convert Edwards-curve coordinates to Montgomery $u$-coordinates via:
     $$u = \frac{1 + y}{1 - y} \pmod{2^{255} - 19}$$
   - Leverage `filippo.io/edwards25519` to extract affine $y$-coordinates and map to `crypto/ecdh.X25519()`.

3. **Key Derivation (HKDF-SHA256)**:
   - Extract and expand shared channel keys using RFC 5869:
     - `PRK = HKDF-Extract(salt = session_salt, IKM = ECDH(peerA, peerB))`
     - `K_enc = HKDF-Expand(PRK, info = "shh-dm-chacha20-poly1305", L = 32)`

4. **Payload Encryption (ChaCha20-Poly1305 AEAD)**:
   - Each DM message frame must be encrypted using ChaCha20-Poly1305 (RFC 8439).
   - Use a strictly monotonic 96-bit sequence counter for nonces to prevent replay attacks.

5. **Memory Hygiene & Zeroization**:
   - Never log or persist plaintext messages, private keys, or derived symmetric keys.
   - Wiping helper (`memclr`): ensure any byte slice containing key material or decrypted message payloads is explicitly cleared before deallocation or channel closure.

---

## 5. Terminal UI & Interaction Guidelines

The TUI must implement a responsive dual-pane layout using `charmbracelet/bubbletea` and `lipgloss`:

- **Left Pane**: Online peer roster (status indicator, nick, idle/active indicator, self marker).
- **Right Pane**: Active DM conversation viewport (peer fingerprint header, encrypted message backlog, cipher badge).
- **Bottom Bar**: Text input bar for typing messages and slash commands.

### Key Navigation
- `Tab` / `Shift-Tab`: Focus navigation between peer roster, message backlog, and text input.
- `Up` / `Down`, `j` / `k`: Roster navigation or viewport scrolling.
- `Enter`: Open DM with selected peer or dispatch input buffer.
- `Esc`: Return focus to roster, dismiss channel, or clear buffer.
- `Ctrl+L`: Trigger redraw / SIGWINCH repaint.
- `Ctrl+C` / `Ctrl+D`: Terminate SSH session gracefully and scrub memory.

### Slash Commands
- `/nick <handle>`: Request or change display handle (bound to public key).
- `/whois <handle>`: View peer's key algorithm, SHA-256 fingerprint, uptime, and cipher suite.
- `/keys`: Display active channel's derived symmetric keys, salt vectors, and frame counters.
- `/clear`: Flush current channel's in-memory backlog.
- `/quit`: Disconnect cleanly.

---

## 6. Build, Test & Run Workflows

Always use the standard commands provided in the `Makefile`:

- **Build**:
  ```bash
  make build
  ```
  Produces the binary at `bin/shh`.

- **Run**:
  ```bash
  make run
  # Runs: go run ./cmd/shh -p 2222
  ```

- **Test**:
  ```bash
  make test
  # Runs: go test -v -race ./...
  ```

- **Clean**:
  ```bash
  make clean
  ```

---

## 7. Test-Driven Development (TDD) Rules

> [!IMPORTANT]
> **Strict TDD Requirement**: We always write tests before writing production code.

Every feature, refactor, bugfix, and cryptographic or networking component must follow the strict Red-Green-Refactor cycle:
1. **Red**: Define the interface and write unit or integration tests *first* specifying expected behaviors, boundary conditions, and failure modes. Verify that tests fail as expected.
2. **Green**: Write the minimum clean implementation code necessary to satisfy the test suite.
3. **Refactor & Verify**: Clean up, optimize, and verify with race detection enabled (`go test -v -race ./...`).
4. **Zero Untested Code**: Never introduce production code (crypto primitives, peer registries, channel buffers, UI handlers) without preceding test cases.

---

## 8. Engineering & Code Guidelines

- **Standard Go Practices**: Code must follow standard Go conventions (`gofmt`, `go vet`).
- **Concurrency & Thread Safety**: All shared peer registries and channel state must be guarded by proper synchronization primitives (`sync.RWMutex`, atomic counters, or channel coordination). Run tests with `-race`.
- **Graceful Shutdown**: Always capture `os.Interrupt` and `SIGTERM` to close client SSH sessions and wipe in-memory sensitive buffers cleanly.
- **Maintain Documentation Integrity**: Keep comments, docstrings, and specifications up to date. Avoid unnecessary CGO dependencies or external system tools.

---

## 9. Roadmap Tracking & Synchronization (`roadmap.md`)

> [!IMPORTANT]
> **Mandatory Roadmap Alignment**: The AI must actively follow, execute against, and maintain `roadmap.md`.

- **Single Source of Truth**: All architectural milestones, cryptographic phases, daemon features, and tasks must be tracked in `roadmap.md`.
- **Pre-Task Verification**: Before picking up or transitioning to any task, consult `roadmap.md` to verify current milestones, dependencies, and prioritized items.
- **Continuous Progress Updates**:
  - Immediately check off completed items (`[x]`) in `roadmap.md` as soon as their tests and implementations pass.
  - When new technical requirements, edge cases, or subtasks are uncovered during implementation, immediately document them under the corresponding milestone in `roadmap.md`.
  - Maintain the active status block (`Current Milestone`, `In Progress`, `Next Up`) in `roadmap.md` so the current project state is always clear and transparent.
- **Never Leave Stale State**: Never finish a user prompt or milestone without synchronizing completed work, new discoveries, and next steps into `roadmap.md`.

---

## 10. Multi-Agent Architecture & Review Protocol

To ensure rigorous quality, cryptographic safety, and focused context, execution is organized into a specialized multi-agent hierarchy: one dedicated implementation agent per phase, plus an independent review agent gating all phase completions.

### Agent Roster & Division of Responsibilities

1. **Orchestrator / Coordinator (Parent Agent)**:
   - Tracks global roadmap state in `roadmap.md`.
   - Spawns and manages subagents for each phase.
   - Synchronizes state, handles user interaction, and gates progression.

2. **Phase-Specific Implementation Agents** (One Agent per Phase):
   - **Phase 1 Agent (`Crypto & Memory`)**: Implements `internal/crypto` (Edwards-to-Montgomery conversion, ECDH, HKDF, ChaCha20-Poly1305, `memclr`).
   - **Phase 2 Agent (`Peer Registry`)**: Implements `internal/peer` (public key pinning, thread-safe registry, nick reservation, presence).
   - **Phase 3 Agent (`Ephemeral Channel`)**: Implements `internal/channel` (RAM ring-buffers, sequence nonces, frame sealing, channel zeroization).
   - **Phase 4 Agent (`SSH Daemon`)**: Implements `internal/daemon` (Wish listener, RFC 4252 public-key auth hook, host keys, session lifecycle).
   - **Phase 5 Agent (`Terminal UI`)**: Implements `internal/ui` (Bubble Tea model, Lipgloss dual panes, slash commands, keybindings).
   - **Phase 6 Agent (`CLI & Integration`)**: Implements `cmd/shh` (CLI flags, end-to-end integration tests, loopback verification).

   *Rule*: Each Phase Agent operates strictly under TDD (tests written and failing before production code is introduced).

3. **Independent Review Agent**:
   - Invoked at the conclusion of each phase before marking the milestone complete.
   - **Audit Checklist**:
     - **TDD Compliance**: Verify all behaviors and edge cases have dedicated test cases.
     - **Test & Race Execution**: Execute `go test -v -race ./...` and ensure 100% pass without data races.
     - **Cryptographic & Memory Hygiene**: Verify zero disk writes, proper wiping (`memclr`) of sensitive buffers, correct nonce monotonicity, and zero leaks in logs.
     - **Concurrency & Goroutines**: Ensure no goroutine leaks, proper context cancellations, and clean mutex locking.
   - **Sign-off Gate**: A phase cannot be marked completed in `roadmap.md` without positive sign-off from the Review Agent. If issues are found, the phase agent must address them before approval.

### Phase Lifecycle Flow

```text
[Orchestrator]
      │
      ▼ (invoke Phase Agent)
[Phase Implementation Agent]
      │  • TDD: Red -> Green -> Refactor
      │  • Verifies local package tests
      ▼
[Review Agent]
      │  • Audits code quality, TDD compliance, crypto hygiene
      │  • Runs `go test -v -race ./...`
      │
      ├───► [Rejections / Issues] ──► Handed back to Phase Agent to fix
      └───► [Approved] ────────────► Orchestrator marks Phase complete in roadmap.md
```

