# JOCKY

[![ci](https://github.com/A73r0id/jocky/actions/workflows/ci.yml/badge.svg)](https://github.com/A73r0id/jocky/actions/workflows/ci.yml)

A purpose-built scripting language and runtime for computer & network
forensic analysis that executes without tripping security tooling.

Built for Smart India Hackathon 2026, problem statement **SIH26148**
(National Technical Research Organisation): *"Creation of scripts/functions
with new programming language to commence Computer & Network forensic
analysis without triggering security solutions."*

## What it is

JOCKY compiles forensic scripts (`.jck`) into self-contained bytecode
images (`.jcx`) that a small stack VM executes **entirely in memory** —
no files written, no child processes spawned, no interpreter dropped on
the examined host. Images can be mutated into polymorphic variants (every
build is a structurally unique binary with identical behaviour) and sealed
in a custom encrypted container (`.jxp`). A central controller fans tasks
out to any number of agents, which pull, execute in RAM, and report.

Two runtimes execute the same image format:

- **Python VM** — the reference implementation and the toolchain
  (Windows + Ubuntu, Python 3.10–3.12, zero third-party dependencies).
- **Rust VM** (`native/vm_rs/`) — a native interpreter with no crates.io
  dependencies that produces **byte-identical output** to the Python VM
  (proven on every CI push), talks to OS APIs directly
  (Toolhelp32 / iphlpapi / dnsapi / advapi32, `/proc` on Linux), and can
  run a payload **embedded inside its own binary** (`jocky-rs --embed`).

## How it stays off the radar

1. **Polymorphic builds** — every deployment instance gets a fresh opcode
   permutation, NOP-weaved code, a shuffled constant pool, a re-shuffled
   basic-block layout with re-threaded jumps, and mangled symbol names.
   N builds → N unique sha256 hashes → byte-identical behaviour. No
   stable bytes exist to sign.
2. **Custom encryption** (JYCRYPT1) — keyed stream cipher with an
   encrypt-then-MAC tag; wrong key or one flipped byte is rejected before
   the VM ever sees the payload. The blob format is cipher-agnostic
   (AES-256-GCM is a drop-in upgrade).
3. **In-memory, read-only execution** — payloads live as byte strings in
   RAM; the forensic stdlib only reads (process/socket/ARP/DNS/persistence
   census, file hashing). Images are decoded and executed without ever
   touching disk.

## Quick start

```bash
git clone https://github.com/A73r0id/jocky && cd jocky   # any OS

python -m jocky run examples/hello.jck                   # compile + run in memory
python -m jocky info examples/hello.jck --disasm         # inspect the bytecode
python -m jocky poly examples/triage.jck -n 5 -o builds/ # 5 unique builds
python -m jocky enc examples/triage.jck -o t.jxp         # encrypt (prints a key)
python -m jocky run t.jxp -k <key-hex>                   # verify, decrypt, run

bash demo.sh fast        # 14-stage guided demo, ends "10/10 DEMO CHECKS PASSED"
```

The native VM:

```bash
cd native/vm_rs && cargo build --release
cd ../..                                         # back to the repo root

native/vm_rs/target/release/jocky-rs examples/hello.jck   # run natively
native/vm_rs/target/release/jocky-rs t.jxp -k <key-hex>   # decrypt + execute
native/vm_rs/target/release/jocky-rs --embed              # run the embedded payload
```

## The language in 20 seconds

```c
// triage snippet — JOCKY is C-flavoured, dynamically typed
func main() {
    let tree = proctree();                 // census + anomaly flags
    for (n in tree) {
        if (get(n, "anomaly", false)) {
            log("flagged:", get(n, "pid"), get(n, "name"), "-", get(n, "note"));
        }
    }
    for (e in persistence()) {             // run keys, services, tasks, cron
        if (get(e, "score", 0) >= 2) {
            log("autostart:", get(e, "name"), "->", get(e, "detail"));
        }
    }
    log("sockets:", len(netconns()), "arp:", len(arp()), "dns:", len(dnscache()));
}
```

30 natives ship in the stdlib: `procs`, `proctree`, `netconns`, `arp`,
`dnscache`, `persistence`, `listdir`, `fstat`, `readfile`, `sha256`,
`hexdump`, `sysinfo`, `env`, `exec` (guarded; absent from the native VM)
and friends — implemented with OS APIs directly, so running one spawns
**zero child processes** on any platform.

## Central management

```bash
python -m agents.controller init
python -m agents.controller add t.jxp --tag triage          # queue a task
JOCKY_KEY=<key-hex> python -m agents.controller serve --port 8177 &

JOCKY_KEY=<key-hex> python -m agents.client \
  --controller http://127.0.0.1:8177 --agent-name node-a --once
JOCKY_KEY=<key-hex> python -m agents.client \
  --controller http://127.0.0.1:8177 --agent-name node-b --once   # concurrent agents
```

Agents never persist task material; findings land only on the controller.
`agents/edr.py` (endpoint-sensor discovery + userland hook diff) and
`agents/byovd.py` (vulnerable-driver hunter) are the live detection side.

## Verification

Every push runs the full pipeline on Ubuntu and Windows:

| Gate | Checks |
|---|---|
| `tests/test_smoke.py` | 15 regression tests (language, serialization, poly, tamper) |
| `ci/check_poly_uniqueness.py` | 7 checks: N builds → N unique hashes, byte-identical behaviour, tamper observability, encryption round-trip |
| `ci/parity_check.py` | 6 checks: Python VM ↔ Rust VM byte-identical output, JYCRYPT1 crypto twin, tamper rejection, shuffled-CFG variants |

```bash
python tests/test_smoke.py
python ci/check_poly_uniqueness.py -n 8
python ci/parity_check.py        # needs the native VM built
```

## Repository layout

```
jocky/            language toolchain + Python VM (lexer, parser, compiler,
                  bytecode, poly, crypto, vm, stdlib)
native/vm_rs/     native Rust VM (value, sha256, crypto, bytecode, vm, payload)
agents/           controller, client, transport, byovd hunter, edr analysis
ci/               poly-uniqueness gate + cross-VM parity gate
examples/         hello / triage / stealth / netprobe (.jck)
tests/            15 regression tests
docs/             architecture, codebase guide, demo script, roadmap
demo.sh           14-stage guided demo
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — design, container format,
  threat model, and why a custom IR instead of an LLVM frontend (§8)
- [docs/CODEBASE_GUIDE.md](docs/CODEBASE_GUIDE.md) — file-by-file tour +
  full command reference
- [docs/DEMO.md](docs/DEMO.md) — demo talking points and Q&A
- [docs/evasion_roadmap.md](docs/evasion_roadmap.md) — in-memory execution
  techniques and their detection signatures
- [docs/ROADMAP.md](docs/ROADMAP.md) — future work

## Scope note

JOCKY is a **defensive forensic framework**: the stealth properties exist so
triage can run on live, monitored hosts without polluting the evidence or
alerting on benign activity. The BYOVD and EDR modules detect vulnerable
drivers and endpoint sensors; they do not disable or evade them. The
transport layer ships as a lab mock for the same reason. See
`docs/architecture.md` §3 for the full threat model and honest limits.
