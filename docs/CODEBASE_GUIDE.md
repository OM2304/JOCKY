# JOCKY Codebase Guide — every file, every command

> Read this once and you can defend any line of the project in front of a
> judge. Companion docs: `README.md` (pitch), `docs/architecture.md`
> (design), `docs/DEMO.md` (presentation script), `native/vm_rs/STATUS.md`
> (native VM state).

---

## 1. The one-paragraph mental model

JOCKY is a **forensic scripting framework**. An analyst writes a script in
the JOCKY language (`.jck`). The **toolchain** (pure Python, runs on the
analyst's machine — the "factory") compiles it into a self-contained
bytecode image (`.jcx`), can mutate it into polymorphic variants and wrap
it in custom encryption (`.jxp`). The **runtime** ("vehicle") is either the
Python VM or the native Rust VM — both execute the *same* image entirely in
RAM: no files written, no child processes, nothing for AV/EDR behavioural
heuristics to catch. The `agents/` layer is central management: a
controller queues encrypted tasks, any number of agents pull, execute
in-memory, and report. `byovd.py` / `edr.py` are the *detection* side:
finding vulnerable drivers and endpoint sensors on a host.

```
ANALYST MACHINE                     TARGET HOST
.jck source                         .jcx / .jxp blob  ──or──  jocky-rs.exe
   │  lexer→parser→compiler            │ (byte string in RAM)     (payload embedded)
   │  poly → encrypt                   ▼                           ▼
   └──────────────► .jcx/.jxp ────►  VM (Python or Rust) ────► findings only
```

---

## 2. `jocky/` — the language + toolchain (pure Python, zero dependencies)

| File | What it is | Judge-worthy details |
|---|---|---|
| `lexer.py` | Tokenizer: identifiers, numbers, strings, operators, `//` comments | First of the three compile stages |
| `parser.py` + `ast_nodes.py` | Pratt (precedence-climbing) parser → AST dataclasses | Pratt parsers handle operator precedence without deep recursion |
| `compiler.py` | AST → stack bytecode. `compile_parts()` gives the raw instruction list + const pool + func table (used by the poly engine); `compile_source()` gives a packed image directly | Function calls compile to `PUSHARG … CALL idx`; locals are name-keyed slots resolved through the const pool |
| `bytecode.py` | **The container format `JY_IMG01`** + assembler/disassembler | Sections: `OPTS` (opcode permutation), `CPOL` (zlib+pickle consts, Python-only), `CPOR` (portable binary consts, read by the Rust VM), `CODE`, `FUNC`, `ENTR`, `HASH` (sha256 of CODE — tamper evidence + per-build identity) |
| `poly.py` | **The polymorphic engine (PS req #2)** | Four passes per build, all semantics-preserving: (1) opcode permutation, (2) NOP weaving with jump re-mapping, (3) **basic-block shuffling + jump threading** (the CFG pass — blocks are split at branch targets/func entries, emitted in a random order, broken fall-throughs re-threaded with explicit JMPs), (4) per-build symbol mangling (`main` → `main_5466`) + constant-pool shuffle. Net: N builds, N unique sha256, **byte-identical behaviour** (proven by the CI gate) |
| `crypto.py` | **JYCRYPT1 custom encryption** | Blob = `MAGIC(8) | salt(8) | tag(32) | ciphertext`. Keystream: Xoshiro256** seeded from sha256(key‖salt) — all four 64-bit state words (hardened from the original 64-bit seed) + 8 warm-up rounds. Tag: `sha256(salt‖ct‖"JOCKY:"‖key)` — verified **before** the VM sees anything. Format is cipher-agnostic: swap the stream for AES-256-GCM with zero layout change |
| `vm.py` | The stack VM (reference implementation) | Executes decoded images fully in RAM; `MAX_STEPS = 20M` runaway guard; marker-based calling convention; `HALT`/`RET` end execution. **Zero file I/O in the whole file** — the in-memory claim is literal |
| `stdlib.py` | The 30 native functions scripts can call | All read-only census: `log len type str int join split upper lower contains get keys now hostname cwd env sysinfo sleep listdir fstat readfile sha256 hexdump procs netconns exec persistence proctree arp dnscache`. Windows: Toolhelp32 (processes), GetExtendedTcp/UdpTable (sockets), GetIpNetTable (ARP), DnsGetCacheDataTable (DNS), registry + Tasks XML (persistence) — **no child processes anywhere**. Linux: `/proc` + `/etc` equivalents. `exec` is the one deliberate exception (bounded, opt-in, absent from the native VM). **NATIVE ORDER IS LOAD-BEARING** — indices are baked into bytecode; only append |
| `__main__.py` | The CLI (`build / run / poly / enc / info`) | `run` accepts `.jck`, `.jcx`, or `.jxp -k key` — decrypt → decode → execute, all in RAM |

**Why two const-pool encodings?** `CPOL` (pickle) is convenient for Python;
pickle is a code-execution risk and unparseable in Rust, so every image
also carries `CPOR`, a trivial length-prefixed binary encoding
(type/len/value) the native VM reads. Python ignores `CPOR`, Rust ignores
`CPOL` — same image, two runtimes.

## 3. `native/vm_rs/` — the native Rust VM (PS: "native components")

| File | What it is |
|---|---|
| `src/value.rs` | JOCKY runtime values with **Python-parity**: shortest-round-trip float repr (`1e+16` vs `1000000000000000.0` rules), floor-mod for negatives (`-7 % 3 == 2`), truthiness, equality/ordering, arithmetic promotion (int+int→int, any float→float, DIV always float) |
| `src/sha256.rs` | Pure-Rust SHA-256 (FIPS 180-4), known-vector tested |
| `src/crypto.rs` | The JYCRYPT1 **twin** — must match Python bit-for-bit, including the deliberate deviation that the keystream uses a truncating shift, not the canonical xoshiro rotate |
| `src/bytecode.rs` | Image parser: inverse permutation table, CPOR const decode, FUNC table |
| `src/vm.rs` | The stack machine (behavioural port of `vm.py`) + all 30 natives via OS APIs (FFI: kernel32/iphlpapi/dnsapi/advapi32 on Windows, `/proc` on Linux) |
| `src/payload.rs` + `embedded/payload.jcx` | Embedded-payload mode: `include_bytes!` at compile time; `jocky-rs --embed` runs the payload straight from the binary's memory — it never exists on disk |
| `src/main.rs` | CLI: `jocky-rs image.jcx`, `jocky-rs payload.jxp -k <hex>`, `--embed`, `--info`. Errors mirror the Python CLI (`jocky: error: …`, exit 1) |

**The proof that matters:** `ci/parity_check.py` (6 checks) — hello and
stealth outputs are byte-identical between Python and Rust on the same
image; a Python-encrypted `.jxp` is decrypted+executed by Rust; a tampered
blob is rejected; and a **shuffled-CFG polymorphic variant** runs
identically on both VMs. Python is the reference; Rust is proven against
it on every CI push.

## 4. `agents/` — central management (PS: "multiple systems simultaneously")

| File | Role |
|---|---|
| `controller.py` | Dependency-free HTTP server. `init / add / serve / mockcdn`. Claim-based work queue (`/api/v1/task` marks a task `taken`); reports stored under `agents/var/reports/` with millisecond filenames (collision-proof under concurrency). The controller **never sees task keys** — payloads stay encrypted end-to-end |
| `client.py` | The agent loop: ping → pull task → JYCRYPT1-verify+decrypt **in RAM** → run in VM → post findings. `DISK_FREEZE` assertion guarantees the payload path never touches disk. `--agent-name` distinguishes concurrent agents |
| `transport.py` | Two lab-safe channels: `MockCDN` (Host-header domain-fronting semantics, no real CDN abuse) and the cloud-API dead-drop model. Honest framing: fronting is ToS-sensitive in the real world, so the lab mock demonstrates the *mechanism* |
| `byovd.py` | **BYOVD hunter (detection)**: vulnerable-driver DB (CVE/CVSS/capability), on-disk + loaded (EnumDeviceDrivers) + SCM cross-validation — and it flags when psapi looks *shimmed/filtered* by an endpoint agent (falls back to the SCM oracle) |
| `edr.py` | **EDR sensor analysis (detection)**: discovers 24 endpoint products via services/registry/processes/in-process DLLs; disk-vs-memory hook diff of hot ntdll/kernel32 exports with trampoline classification (e9/mov-rax/ff25/push-ret/SSN-swap); `--roadmap` prints the defender playbook. `--demo` layers synthetic positives over live discovery |

## 5. `ci/` + `.github/workflows/ci.yml` — the pipeline (PS: CI/CD)

| File | What it enforces |
|---|---|
| `check_poly_uniqueness.py` | 7 checks: round-trip, N unique hashes, **byte-identical behaviour across all builds**, HASH+CODE tamper observability, live process census, enc round-trip |
| `parity_check.py` | 6 cross-VM checks (see §3) |
| `ci.yml` | Jobs: **tests** (Python 3.10/3.11/3.12 × ubuntu/windows) → **build artifacts** (images, poly variants, encrypted payloads, hash-uniqueness assert) → **native-vm** (cargo build+test on both OSes + the parity gate) |

Every push re-proves the claims. The artifacts job uploads fresh
`.jcx`/`.jxp` files whose hashes are asserted unique — deployment-instance
uniqueness as a downloadable fact.

## 6. Everything else

| Path | What |
|---|---|
| `examples/*.jck` | `hello` (language tour), `triage` (incident report: procs+anomalies, persistence, net, ARP, DNS), `stealth` (read-only file hashing), `netprobe` (socket census) |
| `tests/test_smoke.py` | 15 regression tests (language, serialization, poly uniqueness+behaviour, tamper, Linux /proc parsing edge cases) |
| `demo.sh` / `demo.bat` | 14-stage presentation demo ending `RESULT: 10/10 DEMO CHECKS PASSED`; stage 12 runs **two concurrent agents** |
| `docs/` | `architecture.md` (design + the LLVM/Python position, §8), `DEMO.md` (stage-by-stage talking points + Q&A), `evasion_roadmap.md` (in-memory techniques + their detection side), `CODEBASE_GUIDE.md` (this file), `ROADMAP.md` (future work) |

---

## 7. Command cheat sheet (memorise these)

```bash
git clone https://github.com/A73r0id/jocky && cd jocky   # Windows: use Git Bash

# ---- the language toolchain -------------------------------------------
python -m jocky run examples/hello.jck          # compile+run in RAM
python -m jocky build examples/triage.jck -o out.jcx   # compile to image
python -m jocky info out.jcx --disasm           # inspect sections + bytecode
python -m jocky poly examples/triage.jck -n 5 -o builds/  # 5 unique builds
python -m jocky enc examples/triage.jck -o p.jxp -k <hex> # encrypt (key = 64 hex chars = 32 bytes)
python -m jocky run p.jxp -k <hex>              # verify+decrypt+run in RAM

# ---- the native VM -----------------------------------------------------
native/vm_rs/target/release/jocky-rs.exe out.jcx        # run image natively
native/vm_rs/target/release/jocky-rs.exe p.jxp -k <hex> # native decrypt+run
native/vm_rs/target/release/jocky-rs.exe --embed        # run embedded payload
native/vm_rs/target/release/jocky-rs.exe --info out.jcx # image internals
cd native/vm_rs && cargo build --release && cargo test --lib     # build+test

# ---- central management ------------------------------------------------
python -m agents.controller init                          # prepare var/
python -m agents.controller add p.jxp --tag mytask        # queue a task
JOCKY_KEY=<hex> python -m agents.controller serve --port 8177 &   # server
JOCKY_KEY=<hex> python -m agents.client --controller http://127.0.0.1:8177 \
  --agent-name lab-node-a --once                          # one agent cycle

# ---- detection modules ---------------------------------------------------
python agents/edr.py            # live EDR/AV discovery + userland hook diff
python agents/edr.py --roadmap  # defender verification playbook
python agents/byovd.py          # live vulnerable-driver triage
python agents/byovd.py --demo   # synthetic positive demo

# ---- verification (the "prove it" commands) -----------------------------
python tests/test_smoke.py                 # 15 tests
python ci/check_poly_uniqueness.py -n 8    # poly gate (7 checks)
python ci/parity_check.py                  # cross-VM parity (6 checks)
bash demo.sh fast                          # full 14-stage demo -> 10/10

# ---- rebuild the embedded payload ---------------------------------------
python -m jocky build examples/hello.jck -o native/vm_rs/embedded/payload.jcx
cd native/vm_rs && cargo build --release

# ---- git -----------------------------------------------------------------
git add -A && git commit -m "..." && git push     # CI re-runs on every push
```

**Demo-day one-liner:** `bash demo.sh fast`, then immediately
`python agents/edr.py` and `python agents/byovd.py` to show the *live*
(un-plugged) detection side on the judges' own view of the host.
