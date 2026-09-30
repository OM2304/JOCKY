# JOCKY — In-Memory Execution Roadmap (research + forensic companion)

> Scope: this document explains *why* the JOCKY VM runs payloads purely in
> memory, how common in-memory execution techniques work, and — most
> importantly for an NTRO forensic mission — **the detection side of each
> technique**. JOCKY is a forensics tool: its stealth property ("does not
> trigger security solutions") exists so triage can run on live, monitored
> hosts without polluting the very evidence it is collecting.
>
> Nothing in this file is a payload. It is the analysis playbook a forensic
> examiner uses to recognise each technique when it appears in the wild, and
> the engineering rationale for JOCKY's architecture.

---

## 1. Why in-memory execution at all?

A forensic triage script that writes `.exe`/`.py` files, spawns interpreters,
or drops batch files on a victim host:

1. **Modifies the evidence surface** — timestamps, registry `MRU`, AV scan
   caches, file-system journal — i.e. destroys the very data it is meant to
   preserve;
2. **Triggers the security stack** — any local AV/EDR with behavioural
   detection will flag "new executable + immediate execution" chains;
3. **Leaves forensic residue** — every write is a new lead for the opposing
   examiner to chase.

JOCKY therefore compiles source to a packed image (`JY_IMG01`), optionally
encrypts it (`JYCRYPT1`), and executes it **entirely inside one Python (or
Rust-native) process's address space**. The payload is a byte string in RAM;
no file ever touches disk on the target. That single architectural decision
answers the problem statement's central constraint: *forensic analysis
without triggering security solutions*.

| Technique | Disk writes | New processes | File regs | Detection risk |
|---|---|---|---|---|
| Classic script (baseline) | yes | yes | yes | **very high** |
| JOCKY `.jcx` direct `run` | none | none | none | low (RAM only) |
| JOCKY agent (`.jxp` fetched over C2) | none | none | none | low (RAM only) |

---

## 2. The five canonical in-memory techniques (and their footprints)

These are the techniques an examiner will meet in modern red-team tooling.
For each we give: how it works, the forensic indicators it leaves, and the
detection/mitigation that surfaces it. The **indicator column is the NTRO
deliverable** — it is what JOCKY's sister modules (`agents/edr.py`,
`agents/byovd.py`) automate.

### 2.1 Process hollowing (injection into a suspended process)

**How it works**
1. Spawn a benign process (`C:\Windows\System32\...`) in `SUSPENDED` state.
2. Unmap its image (`NtUnmapViewOfSection`) or map a fresh region.
3. Write the malicious image over the hole, fix up relocations, point the
   thread at the new entry point, resume.

**Forensic indicators / detection side**
- Parent/child process tuples that make no sense (e.g. `word.exe` spawning
  `cmd.exe` — even for forensic tooling: `chrome` spawning nothing).
- The suspended window: thread state stuck at `SUSPENDED`/`STOPPED` at
  creation followed by a resume — visible in memory dumps.
- **Section mapping count**: the process's mapped images internally
  inconsistent with disk (a memory dump shows two PE headers for one image,
  or a PE whose disk counterpart hashes differently).
- `NtUnmapViewOfSection` / `NtClose` + `NtWriteVirtualMemory` call
  sequences in the API log.
- Detection: EDR memory-integrity checks (hash the resident sections),
  `YARA mem` rules for known "shellcode-in-suspended-proc" patterns.

### 2.2 Reflective DLL injection (a DLL that loads itself)

**How it works**
- A loader stub copies a DLL image into RWX memory, walks its PE structures
  *manually* (no `LoadLibrary`), resolves imports via its own resolver, calls
  `DllMain`/entry from a thread it creates. No file, no `LOAD` event.

**Forensic indicators / detection side**
- **No image-load event**: the DLL's base address appears in the module
  list (or in `Ntdll!` walkers) without a corresponding `LoadImage` LEB
  (kernel-level event) — a classic gap.
- **RWX page containing an MZ header** — scan for `4D 5A` at the start of
  writable+executable regions (the single most reliable in-memory marker).
- Import address table (IAT) entries pointing at *unusual* pages (not into a
  known file-backed module) — a ".gotcha" for `GetProcAddress` during
  resolution.
- Detection: periodic EMT (execute-memory-test), page-permission scans,
  `Volatility` `malfind`/`procdump` on `RX`+`WX` regions containing PE
  signatures.

### 2.3 API unhooking (restoring stubs so the sensor is bypassed)

**How it works**
- EDR sensors rely on userland API hooks (see `agents/edr.py`). The
  operator looks up the *clean* ntdll stub (from a fresh copy on disk or
  another process) and overwrites the trampoline bytes in its own copy —
  restoring the original `mov rax,r10; mov r10,rcx; syscall` prologue.

**Forensic indicators / detection side**
- This is exactly what `agents/edr.py` automates: disk-vs-memory diff of the
  first N bytes of hot exports. A *clean* memory stub where disk is clean is
  **normal**; a memory stub *different from disk* is a hook (either the
  sensor's own hook — or the operator's unhook, if the sensor itself is
  invisible at that moment).
- **Second-chance hooks**: resilient EDRs hook syscall *wrappers* plus the
  syscall `int 2Eh` instruction itself, so unhooking userland stubs does not
  remove telemetry — the `int 2E` intercept fires at the boundary.
- Detection: `agents/edr.py --hooks`; kernel EDRs can compare the resident
  stub hash against the disk hash from inside the kernel.

### 2.4 Direct/indirect syscalls (skipping userland entirely)

**How it works**
- Instead of calling `NtX` in ntdll (which the EDR hooks), issue the `syscall`
  instruction directly with the right syscall number (SSN) in `rax`.
  Indirect variant: `jmp` through a benign DLL's gadget / use `rwx` trampoline.

**Forensic indicators / detection side**
- **Thread instruction offset**: an executing thread whose RIP is inside a
  *non-module* page (RWX trampoline), or whose return address walks outside
  any mapped image — visible in memory forensics as suspicious call stacks.
- Syscall numbers used that do not match the thread's module set / a
  mismatch between ntdll version and the SSN table in use
  (`syscall_swap` signature in `agents/edr.py`).
- Detection: EDR intercepts at the *kernel* entry (Windows 10+ `Syscall
  interposition`), ETW telemetry on syscall entry, memory dumps showing
  both `rax=SSN` and a return address outside file-backed ranges.

### 2.5 Thread hijacking / async injection

**How it works**
- Take an existing alive thread (or a created `Suspended` pthread), save its
  state, point it at your stub (set `RIP`), let it run, restore.

**Forensic indicators / detection side**
- A thread whose registers point into a RWX region that is *not* its own
  module (register-state analysis of dumps).
- Thread count vs callbacks mismatch (e.g. one thread per 0.5s heartbeat for
  a benign-looking process).
- Detection: thread-local register monitoring (kernelside), `Suspended`
  thread census (`agents/edr.py` roadmap item: audit thread states).

---

## 3. Why JOCKY sidesteps all five (and what it still does *not* claim)

- JOCKY never creates a new process, never maps an image, never unhooks —
  it executes a **bytecode** interpreter loop inside the host interpreter
  process. There is no second PE, no MZ-in-RWX, no suspend/resume dance.
- The `procs`/`netconns`/`listdir`/`readfile` natives are read-only by
  design; `exec` is gated and never implicit.
- **Honest limits** (must be in the judging Q&A):
  - It still *allocates* RAM (normal for any interpreter) and uses normal
    userland APIs (so it is detectable *in principle* by API-hook telemetry —
    it simply does not produce the *behavioural patterns* (file drops,
    process spawning) that make AV flag a host);
  - Anything running on a host with a kernel-level EDR will still generate
    *some* telemetry; "does not trigger" is about *detection heuristics*
    (KillChain triggers), not about being physically invisible;
  - The Rust-native VM (see `native/` and CI job "rust-vm") lowers the
    interpreter footprint and closes the "Python interpreter present" tell.

## 4. The engineering roadmap (priorities)

1. [done] Bytecode VM + poly + crypto → image executes in-process only.
2. [done] C2 agent: fetch `.jxp` → decrypt in RAM → run → report (no disk).
3. [planned] Rust-native VM (`native/jocky-vm`): parse `JY_IMG01`,
   verify `HASH` tag, execute core opcode set — same format, faster loop,
   no interpreter binary needed on the target beyond the single embedded
   executable.
4. [planned] `--drop-mode` variant: embed payload in a single self-contained
   binary (Rust) that *is* the VM; one file, zero writes.
5. [stretch] BPF/qemu-userspace backend for cross-arch forensic triage.

---

## 5. Detection-side automation already shipped (map to this doc)

| Doc section | Automated in |
|---|---|
| 2.3 API unhooking detection | `agents/edr.py` (disk-vs-memory stub diff, hook-type classification, target attribution) |
| 2.4 syscall-SSN tampering | `agents/edr.py` (`syscall_swap` signature) |
| Kernel driver census / BYOVD exposure | `agents/byovd.py` (psapi + SCM cross-validation, vulnerable-driver DB) |
| Sensor inventory (what is watching) | `agents/edr.py` discovery + SecurityCenter2 |
| Policy/pipeline guarantee | `ci/` polymorphic build + hash-unique asserts |