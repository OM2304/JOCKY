# JOCKY — Architecture & Design

> SIH 2026 · PS SIH26148 (NTRO) · "Forensic scripting language that does not
> trigger security solutions"
> Companion to `SESSION_CONTEXT.md`. Last updated: 2026-09-10.

## 1. System overview

JOCKY is a forensics-oriented **domain-specific language plus delivery
toolchain**. Analysts write triage/analysis scripts in JOCKY (`.jck`),
the toolchain compiles them into self-contained **bytecode images** (`.jcx`),
and the runtime executes them **fully in memory**. Nothing the analyst ships
is a script on disk at execution time — it is a packed image inside an
encrypted container, or an embedded constant inside a compiled native binary.

```
.jck source ──lexer──► tokens ──parser (Pratt)──► AST
   ──compiler──► instructions + const pool + func table
   ──compile_and_pack──► Image (JY_IMG01)   ──► .jcx file (portable)
        └── PolymorphEngine──► N builds, N unique hashes (per-deployment mutation)
        └── JYCRYPT1 (XOR stream + keyed tag) ──► .jxp payload (C2 delivery)
   ──► VM (Python or Rust-native), decodes + executes in RAM only
```

Two execution front-ends share the **same container format**:

| Front-end | Role | Notes |
|---|---|---|
| Python VM (`jocky/vm.py`) | Reference implementation, toolchain, agent runtime | zero third-party deps, Windows + Ubuntu |
| Rust VM (`rust/`) | Compiled native component (PS "In-Memory Execution" carry-along) | embeds `.jcx`/`.jxp` in the binary, decrypts+executes in RAM, no crates.io deps |

## 2. Container format — `JY_IMG01`

```
[8B magic "JY_IMG01"][u32 version=1]
repeated sections: [4B tag][u32 size][payload]
```

| Tag | Payload | Notes |
|---|---|---|
| `OPTS` | opcode permutation table (N bytes, N = opcode count) | identity for non-poly builds; enables decoded-at-load polymorphic CODE |
| `CPOL` | zlib-compressed **pickle** of the constant pool | tags must be **exactly 4 bytes** (the `CONST`→`CPOL` truncation bug, fixed 2026-09-10) |
| `CODE` | instruction stream: `[u8 encoded-op][operand bytes]` | operand width is per-opcode; jumps are **absolute byte offsets** |
| `FUNC` | function table: `u32 N`, then per entry `u8 name_id, u8 nparams, u8 param_id…, u32 addr` | no relocations needed |
| `ENTR` | `u32` index of `main` | |
| `HASH` | sha256 of canonical (unpermuted) CODE stream | unique per build after polymorphism |

All integers little-endian. The constant pool is the only Python-ism;
the Rust front-end ships a minimal pickle-decoder for the value types JOCKY
emits (str/int/float/bool/None/list), so images are portable.

## 3. Threat model

JOCKY is an **assistive** capability: the framework should detect
adversaries while its own deployments stay undetected ("nec" = Negative
Effect Control: silent, read-only, short-lived, no residue).

- **Adversary for JOCKY itself**: EDR/AV reputation hashing, static
  signature scanning, behavioural heuristics (child-process anomalies,
  file writes, injection primitives), network egress filtering.
- **Defences in the toolchain**:
  1. Polymorphism (`poly.py`) — defeats file-reputation: N builds of the
     same task have N distinct sha256 hashes and non-overlapping layouts.
  2. Encryption (`crypto.py`) — `.jxp` blobs are keyed stream-ciphered with
     an integrity tag; a wrong key or tamper fails **before** the VM starts.
  3. In-memory execution — the VM never writes task material to disk; the
     Rust front-end runs payloads embedded in the compiled binary.
  4. Read-only script convention — example scripts (`stealth.jck`) perform
     no disk writes, spawn no processes, modify nothing.
- **Adversary that JOCKY detects** (PS side B): BYOVD drivers, EDR
  callbacks/hook tampering, persistence, suspicious process/connection
  census — implemented in `agents/` as *analysis* tooling.

## 4. The two execution front-ends

### 4.1 Python VM (reference)
- Stack machine; calling convention `PUSHARG …CALL/NAT` with frame-based
  locals and an iterator slot per loop variable.
- `MAX_STEPS = 20M` guard against runaway loops.
- Natives (`stdlib.py`, 26) cover the forensic surface: process/connection
  census, file hashing (`sha256`), `hexdump`, env/sysinfo, bounded `exec`.
- Windows paths use `ctypes`; Linux paths use `/proc` + `ss` — the same
  image runs on both (PS: cross-platform compiler).

### 4.2 Rust native component (compiled)
- Pure-`std` Rust, **no crates.io dependencies** (offline-buildable, small,
  audit-friendly). Distribution: a single `.exe`/ELF.
- Embeds a `.jcx` image (and an optional `.jxp` plus key) via
  `include_bytes!` at compile time; at runtime it:
  1. recovers the payload **in RAM** (decrypting with an in-Rust Xoshiro256**
     + sha256 twin of JYCRYPT1 when needed),
  2. inflates the const pool (in-Rust DEFLATE decoder for the zlib stream),
  3. decodes the const pool with a minimal pickle-4 reader,
  4. executes the bytecode with its own stack VM and native bindings.
- Proveable parity: same `.jcx` produces identical `log` output on the
  Python VM and the Rust VM (`rust/README.md` documents the comparison).

## 5. Central management fabric (`agents/`)

- **Controller** (`agents/controller.py`): stdlib HTTP server; task queue of
  `.jxp` payloads; findings endpoint. Serves multiple clients concurrently
  (PS: "handle multiple system analysis simultaneously").
- **Client** (`agents/client.py`): polls → pulls `.jxp` → decrypts in RAM →
  runs in VM → posts findings. No payload material written to disk.
- **Transport** (`agents/transport.py`): two channels per the PS:
  1. *Domain fronting* — the client connects to a CDN-fronted IP but the
     `Host:` header names the front domain; the controller path is a
     CDN-cached route. Instructed as ToS-sensitive; provided with a local
     mock-CDN for lab use.
  2. *Legitimate cloud-API dead-drop* — task blobs and reports ride on
     ordinary webhook/paste-style APIs; traffic is indistinguishable from
     the publisher's normal API traffic. Preferred for reliability today.

## 6. Native-component swap note (hardware AES)

`JYCRYPT1` deliberately keeps **keying outside the blob**: the tag uses
`sha256(salt‖ct‖b"JOCKY:"‖key)` and the keystream is seeded from
`sha256(key‖salt)` — the construction is effectively an encrypt-then-MAC
XOR stream. The blob layout (`MAGIC|salt|tag|ct`) is independent of the
cipher, so hardening deployments may swap the XOR stream for **AES-256-GCM
(software win32crypt / hardware AES-NI)** with zero format changes:

```
old: stream = XOSHIRO256**(seed)           ; XOR
new: stream = AES-256-GCM(key, salt)       ; CTR (same layout, same tag check)
```
The Rust and Go future front-ends can adopt a hardware-accelerated crypto
provider without touching image/agents code.

## 7. Directory map

```
jocky/            language toolchain + VMs (Python)
examples/         .jck showcase scripts (read-only by convention)
tests/            smoke + regression suite (currently 12 tests)
agents/           controller, client, transport, byovd, edr (analysis)
rust/             compiled native front-end (pure std, offline build)
ci/               release-audit script + GitHub Actions workflow
docs/             this doc, evasion roadmap, demo & presentation guides
```
## 8. Why a custom IR instead of an LLVM frontend (and why Python stays)

The PS wording is *"Programming language **or** custom Language-independent
intermediate representation (LLVM) frontend"*. JOCKY takes the **first
branch**: a new programming language with its own IR (`JY_IMG01`). That is
a deliberate engineering choice, not a shortcut:

1. **LLVM bitcode is itself a signatureable format.** A `.bc` file starts
   with fixed magic bytes (`BC 0xC0 DE`) and ships stable, parseable
   metadata; `llvm-dis` is present in every analyst's toolkit. An
   LLVM-based pipeline inherits a *public, versioned container* that
   signature engines can target. JOCKY's IR is private and every build
   permutes it (opcode table, block order, symbol names, NOP padding), so
   there are no stable bytes to write a signature against -- the exact
   property the PS asks for.
2. **The PS's three alteration clauses map to concrete passes** in
   `jocky/poly.py`, all enforced by the CI gate:
   - *binary structures* -- opcode permutation (`OPTS`), NOP weaving,
     constant-pool reordering;
   - *basic control-flow graphs* -- the basic-block shuffler: blocks are
     split at branch targets/function entries and emitted in a fresh random
     order, with fall-through edges re-threaded through explicit jumps
     (8 builds -> 8 distinct CFGs, byte-identical behaviour);
   - *token generation* -- per-build symbol mangling of every function
     name (`main` -> `main_5466` in one build, a different suffix in the
     next).
   LLVM would actively *fight* two of the three: its verifier expects
   well-formed bitcode, and CFG-randomisation on top of opt passes means
   maintaining a fork of LLVM infrastructure for less scrambling than the
   200-line custom pass achieves.
3. **LLVM remains a compatible future backend.** The image format is
   cipher- and producer-agnostic; a `JOCKY -> LLVM IR -> native object`
   emitter (for AOT-hardened deployments) can be added without touching
   the VM, agents, or container.

### Why the Python toolchain is not the "host tell"

The Python tree (lexer/parser/compiler/poly/crypto + reference VM) runs on
the **analyst's machine** -- it is the factory. The artifact that lands on
a *target* is one of:

- a `.jcx`/`.jxp` byte blob executed by whatever front-end is deployed
  there, or
- `jocky-rs` (native, ~2 MB, std-only Rust) with the payload embedded via
  `include_bytes!` (`jocky-rs --embed`): the payload never exists as a
  file, and no interpreter beyond the single compiled binary is needed.

No Python ships to, or executes on, the examined host. The Python VM also
stays as the **reference implementation** for the cross-VM parity gate
(`ci/parity_check.py`, 6/6) -- the native VM is proven byte-identical
against it on every push, which is the strongest correctness story two
independent implementations can have.
