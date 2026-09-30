# jocky-rs — status (2026-09-12)

## What exists (all working)
- `Cargo.toml`: package `jocky-rs` 0.1.0, edition 2021, **stdlib only**
  (deliberately no crates.io deps — offline buildable). Lib + `jocky-rs`
  binary.
- `src/value.rs` — Python-parity value layer: display/repr (incl. shortest
  round-trip float repr via `{:e}`), equality, ordering, truthiness,
  floor-mod, arithmetic with Python promotion rules (int/bool stay int,
  DIV always float, str concat).
- `src/sha256.rs` — pure-Rust SHA-256 (FIPS 180-4) with known-vector tests.
- `src/crypto.rs` — JYCRYPT1 twin: Xoshiro256** keystream (parity with the
  hardened Python KDF: 4 state words = sha256(key||salt) slices, 8 warm-up
  rounds) + tag verify before decrypt. **Truncating-shift parity note:**
  jocky/crypto.py computes `(s1*5) << 7 & MASK` — a shift, NOT the canonical
  xoshiro rotate_left — and this module reproduces that exactly.
- `src/bytecode.rs` — JY_IMG01 parser: OPTS inverse permutation, **CPOR**
  portable const pool (no pickle/DEFLATE needed), CODE, FUNC, ENTR, HASH.
- `src/vm.rs` — stack VM (byte-for-byte behavioural port of jocky/vm.py) +
  30 natives mirroring jocky/stdlib.py: census via Toolhelp32/iphlpapi/
  dnsapi/advapi32 FFI on Windows, /proc on Linux. **Zero child processes
  and zero third-party deps.**
- `src/payload.rs` + `embedded/payload.jcx` — embedded-payload delivery
  vehicle: `include_bytes!` at build time; `jocky-rs --embed` executes the
  image straight from the binary's .rdata (payload never exists on disk).
- `ci/parity_check.py` — cross-VM gate: hello/stealth byte-identical between
  Python VM and this VM, netprobe shape-equal, Python-encrypted `.jxp`
  decrypted+executed here, tampered blob rejected.

## Verified on this machine (2026-09-12)
| Check | Result |
|---|---|
| `cargo test --lib` | 17/17 pass |
| `ci/parity_check.py` | 5/5 (byte-identical + crypto twin + tamper) |
| native triage (`triage.jcx`) | 281 procs (Toolhelp32), 11 anomaly flags, 281 persistence entries, 125 sockets, 22 ARP, 843 DNS names |
| embedded payload | `jocky-rs --embed` runs hello byte-identically |

## Toolchain notes (supersede the 2026-09-11 probe table)
- `rustc 1.98.1` is a standard toolchain; `matches!` and normal std APIs
  work. The old "exotic dialect" blocker no longer exists (probes deleted).
- Two real toolchain quirks we worked around:
  1. `{:.prec$e}` TRUNCATES denormals (`4.9406e-324` → `"4.9e-324"`), so
     `py_float_repr` uses `{:e}` (shortest round-trip) instead — which is
     also exactly what CPython's repr selects.
  2. `PROCESSENTRY32W.pcPriClassBase` must be declared as 4-byte `LONG`;
     an 8-byte field pads sizeof to 576 and Process32FirstW fails with
     ERROR_BAD_LENGTH.

## Known divergences from the Python VM (documented, deliberate)
- `persistence`: scheduled-task XML sweep (System32\Tasks) is Python-only in
  v1 — the native build covers run keys, auto-start services and startup
  folders (no XML parser in std Rust).
- `sysinfo`: `python` field reports `native-rust/jocky-rs <ver>` — proves
  which engine produced a report (a feature for the judges demo).
- `fstat` mode is hard-coded `0o100666` (std::fs exposes no POSIX bits).
- `exec` native is deliberately absent from the native VM (read-only
  surface, zero child processes).
- `procs` Linux returns no `threads` field (not in /proc/<pid>/stat parse).

## Next steps (optional hardening)
1. Embedded `.jxp` mode with build-time key via `option_env!("JOCKY_EMBED_KEY")`.
2. Linux FFI census via netlink (sock_diag) to match the Windows pid detail.
3. `--disasm` in the native CLI (port of `jocky info --disasm`).
